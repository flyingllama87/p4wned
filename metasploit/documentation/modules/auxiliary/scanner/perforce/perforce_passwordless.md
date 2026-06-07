## Description

Detects Perforce (Helix Core) user accounts that have no password set.

Sends the `user-users` command with the tagged output flag (`tag:""`). In
tagged mode the server returns `client-FstatInfo` records per user. The
`Password` field is absent for passwordless accounts. Passwordless accounts
allow direct unauthenticated login — no brute force required.

Auto-detects SSL/TLS and unicode server modes — no manual flags required.

**Affected:** all Perforce server versions with default settings
(`run.users.authorize=0` and `security=0`).

**Remediation:**
```
p4 configure set dm.user.noautocreate=2
p4 configure set security=3
```
Set passwords for all existing accounts.

## Vulnerable Application

### Install a test Perforce server with a passwordless account (Linux)

```bash
# Download p4d and p4 (subject to Perforce terms of use: https://www.perforce.com/legal)
wget https://ftp.perforce.com/perforce/r24.2/bin.linux26x86_64/p4d
wget https://ftp.perforce.com/perforce/r25.2/bin.linux26x86_64/p4
chmod +x p4d p4

# Start a server on port 1666
mkdir p4root_test
./p4d -r ./p4root_test -p 1666 -d

# Create a user without setting a password — this is the vulnerable state.
# At security=0 (default), the server accepts a blank password on login.
./p4 -p 1666 -u admin user -f -i <<EOF
User: svc_build
Email: svc@example.com
FullName: Build Service Account
EOF
```

The account `svc_build` now has no password. At the default `security=0`
level, any client can authenticate as this user with an empty password.

## Verification Steps

1. `use auxiliary/scanner/perforce/perforce_passwordless`
2. `set RHOSTS <target>`
3. `set RPORT 1666`
4. `run`
5. Passwordless accounts are printed, stored to loot, and saved to the
   credential database with an empty password.

## Options

| Option  | Default | Description                          |
|---------|---------|--------------------------------------|
| RHOSTS  |         | Target host(s)                       |
| RPORT   | 1666    | Perforce server port                 |
| TIMEOUT | 10      | Connection and read timeout (seconds)|

## Scenarios

### Passwordless account found

```
msf6 > use auxiliary/scanner/perforce/perforce_passwordless
msf6 auxiliary(scanner/perforce/perforce_passwordless) > set RHOSTS 192.0.2.10
RHOSTS => 192.0.2.10
msf6 auxiliary(scanner/perforce/perforce_passwordless) > run

[+] 192.0.2.10:1666 [tcp] [PASSWORDLESS] svc_build <svc@example.com> "Build Service Account"
[+] 192.0.2.10:1666 [tcp] [PASSWORDLESS] jdoe <jdoe@example.com> "Jane Doe"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The credentials are saved to the database with an empty password and can be
used directly with `auxiliary/scanner/perforce/perforce_login` or the `p4`
CLI binary.

### SSL server (auto-detected)

```
msf6 auxiliary(scanner/perforce/perforce_passwordless) > set RHOSTS 192.0.2.20
RHOSTS => 192.0.2.20
msf6 auxiliary(scanner/perforce/perforce_passwordless) > run

[+] 192.0.2.20:1666 [ssl] [PASSWORDLESS] svc_build <svc@example.com> "Build Service Account"
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Server hardened (all accounts have passwords)

```
msf6 auxiliary(scanner/perforce/perforce_passwordless) > run

[*] 192.0.2.10:1666 - No passwordless accounts found
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
