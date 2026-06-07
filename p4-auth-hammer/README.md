# p4-auth-hammer

Proof-of-concept demonstrating that Perforce (`p4d`) does not effectively rate-limit authentication attempts when `security < 3`. Uses the official Perforce C++ API to sustain >300,000 login attempts per minute against a single account on a default-configured server.

> Authorised targets only. The tool displays a consent prompt and will not run without it.

---

## Background

Perforce's `dm.user.loginattempts` configurable is supposed to limit failed login attempts, but it only functions at `security >= 3` (ticket-based authentication). At the default security level of 0, and at levels 1 and 2, authentication uses the password-based flow where:

1. The client sets a password on the `ClientApi` object and runs any authenticated command (e.g. `depots`).
2. The server checks the password and returns an error or a result.
3. The same `ClientApi` connection can be reused immediately for the next attempt without reconnecting.

There is no lockout. There is no delay. Attempts are limited only by the TCP round-trip time between client and server. On a LAN or local loopback this is effectively zero.

At `security >= 3`, authentication switches to ticket-based login (`p4 login`). The tool supports this mode via `-ticketauth` but the rate at that level is significantly lower because each attempt requires a full login round-trip and a separate command execution.

---

## Build

### Prerequisites

The tool links against the Perforce C++ API (`p4api`) and OpenSSL 1.1.1. The expected directory layout relative to the **repo root** is:

```
reporoot/
  include/
    p4/              ← p4api header files
  lib/               ← p4api static libraries (libp4api.a etc.)
  openssl-1.1.1w/    ← OpenSSL 1.1.1w (only needed if p4api does not bundle it)
  p4-auth-hammer/
    p4_auth_hammer_poc.cpp
    p4_auth_hammer_poc_build.sh
```

**Step 1 — Download the Perforce C++ API:**

```bash
cd /path/to/p4wned-notes

# Linux x86_64, OpenSSL 1.1.1 variant (adjust version as needed)
wget https://ftp.perforce.com/perforce/r25.2/bin.linux26x86_64/p4api-glibc2.3-openssl1.1.1.tgz
tar xzf p4api-glibc2.3-openssl1.1.1.tgz

# The tarball extracts to a versioned directory, e.g.:
#   p4api-2025.2.2000000.linux26x86_64/
#
# Move contents to match the expected paths:
API_DIR=$(tar tzf p4api-glibc2.3-openssl1.1.1.tgz | head -1 | cut -d/ -f1)
mv "$API_DIR/include" include
mv "$API_DIR/lib"     lib
rm -rf "$API_DIR" p4api-glibc2.3-openssl1.1.1.tgz
```

**Step 2 — OpenSSL (if required):**

The `p4api` tarball above is statically linked against OpenSSL 1.1.1 and includes the necessary `.a` files in its `lib/` directory. The `-L../openssl-1.1.1w` path in the build script is only needed if your system's OpenSSL differs and you have a standalone OpenSSL 1.1.1w build. If the build succeeds without it, you can remove that flag. If you need it:

```bash
# Download and build OpenSSL 1.1.1w from source
wget https://www.openssl.org/source/openssl-1.1.1w.tar.gz
tar xzf openssl-1.1.1w.tar.gz
cd openssl-1.1.1w && ./config && make -j$(nproc) && cd ..
```

**Step 3 — Build:**

```bash
cd p4-auth-hammer
bash p4_auth_hammer_poc_build.sh
```

This produces the `p4_auth_hammer_poc` binary in the `p4-auth-hammer/` directory.

Compiler flags used: `-O3 -march=native -flto -funroll-loops` — optimised for throughput on the local machine. Do not distribute the resulting binary; it is machine-specific.

---

## Usage

```
./p4_auth_hammer_poc <server:port> <username> <password_file> [-ticketauth]
```

| Argument | Description |
|---|---|
| `server:port` | Target Perforce server. Use `host:port` for plain TCP or `ssl:host:port` for SSL (auto-detected if omitted). |
| `username` | The account to attack. |
| `password_file` | Wordlist — one password per line. |
| `-ticketauth` | Use ticket-based login (`p4 login`) instead of direct password auth. Required for `security >= 3` servers, but significantly slower. |

**Example:**

```bash
./p4_auth_hammer_poc 192.0.2.10:1666 admin top-passwords.txt
./p4_auth_hammer_poc 192.0.2.10:1666 admin top-passwords.txt -ticketauth
```

The tool displays a consent prompt (`Type 'YES' to continue`) and will not proceed without it.

---

## Auth Modes

### Standard mode (default — `security < 3`)

Sets the password directly on the `ClientApi` connection object and runs `depots` to probe authentication. The connection is held open and reused across attempts — no reconnect overhead. This achieves >300,000 attempts per minute on a local or low-latency network.

Rate-limiting (`dm.user.loginattempts`) has no effect in this mode.

### Ticket mode (`-ticketauth` — `security >= 3`)

Runs `p4 login` for each attempt, supplying the password via the `Prompt()` callback. This is the correct path for ticket-based servers where direct password setting is rejected. Significantly slower than standard mode due to the login round-trip cost. Rate-limiting is effective at `security >= 3`.

---

## Auto-Detection

The tool detects server requirements at runtime and reconfigures automatically — no flags needed beyond the basic connection details:

| Condition | Detection | Action |
|---|---|---|
| SSL-only server | Server returns `"server using SSL"` / `"Client must add SSL protocol prefix"` error on plain TCP connection | Reconnects with `ssl:` prefix; writes server fingerprint to `./poc_trust.txt` |
| Unicode server | Server returns `"Unicode server permits only unicode enabled clients"` | Sets `CharTrans(1)` (unicode mode) and reconnects |
| SSL certificate trust | Server returns fingerprint prompt | Parses fingerprint from error message and writes to `./poc_trust.txt` |

The trust file (`./poc_trust.txt`) is written with `chmod 400` (read-only) to satisfy Perforce's trust file permission requirements.

---

## Thread Tuner

The tool automatically finds the optimal thread count for the target server. It starts with `nproc` threads (hardware concurrency) and adjusts based on measured throughput:

| Phase | Strategy | Description |
|---|---|---|
| **Probing (×2)** | Doubles thread count each cycle | Finds the ballpark quickly |
| **Probing (+10)** | Increments by 10 each cycle | Fine-tunes around the peak |
| **Locked** | Holds at best count | Stops tuning; runs at optimal throughput |

Tuning exits the probing phase early if connection errors exceed 10% of attempts, falling back to a stable count of `max(nproc, 4)`.

Progress display during a run:
```
[Probing (x2)] Threads: 64 | T/put: 284320.4/s (Best: 284320.4) | Progress: 142160/500000 | Fails: 142159 | Err: 0
```

---

## Example Output

```
$ ./p4_auth_hammer_poc 192.0.2.10:1666 admin passwords.txt

*** WARNING: PERFORCE AUTHENTICATION RATE PoC ***
This will attempt thousands of logins against the target.
Run ONLY against servers you own or have permission to.
Type 'YES' to continue: YES

[INFO] Loaded 500000 passwords.
[INFO] Starting with 8 threads...

[Probing (x2)] Threads: 16  | T/put: 91203.2/s  (Best: 91203.2)  | Progress: 45601/500000  | Fails: 45600  | Err: 0
[Probing (x2)] Threads: 32  | T/put: 178442.1/s (Best: 178442.1) | Progress: 134521/500000 | Fails: 134520 | Err: 0
[Probing (x2)] Threads: 64  | T/put: 284320.4/s (Best: 284320.4) | Progress: 284521/500000 | Fails: 284520 | Err: 0
[Probing (x2)] Threads: 128 | T/put: 271005.8/s (Best: 284320.4) | Progress: 420821/500000 | Fails: 420820 | Err: 0
[Probing (+10)] Threads: 74 | T/put: 291887.3/s (Best: 291887.3) | Progress: 456201/500000 | Fails: 456200 | Err: 0
[Locked]        Threads: 74 | T/put: 312001.0/s (Best: 312001.0) | Progress: 499998/500000 | Fails: 499997 | Err: 0

--- Summary ---
Total Time:    1.6021 s
Successes:     0


$ ./p4_auth_hammer_poc 192.0.2.10:1666 admin passwords.txt

...

==================================================
[CRITICAL] SUCCESSFUL AUTHENTICATION FOUND!
       Server: 192.0.2.10:1666
         User: admin
     Password: Password1
       Method: Standard (direct auth)
==================================================

--- Summary ---
Total Time:    0.8342 s
Successes:     1
```

---

## Remediation

Set `security=3` or higher. This forces ticket-based authentication, at which point `dm.user.loginattempts` functions as documented.

```
p4 configure set security=3
```

`security=4` is the fully hardened setting and additionally disables the remote depot exploit. See the top-level README for the full hardening checklist.
