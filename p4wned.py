print(r"""
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
""")


import subprocess
import socket
import re
import sys
import os
import argparse
import threading
import time
import concurrent.futures
from functools import partial
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any

timestamp = int(time.time())

# Configuration
CONFIG = {
    "INPUT_FILE": "perforce-servers.txt",
    "MY_MACHINE": "localhost",
    "MY_WORKING_DIR": "/tmp",
    "P4_CMD": "./p4",
    "REPORT_FILE": f"perforce-report-p4wned-{timestamp}.txt",
    "TOP_PASSWORDS_FILE": "top-passwords.txt",
    "KNOWN_CREDS_FILE": "master-known-credentials.txt",
    "FALLBACK_USERS": [
        "perforce", "p4admin", "p4super", "admin", "user", "developer", "render", "root", "administrator", "Admin", "p4", "swarm", "build", "Swarm", "jenkins", "runner", "Administrator", "guest", "Perforce", "P4", "Jenkins", "teamcity"
    ]
}

OPTIONS = {
    "BRUTE_MODE": False,
    "AUDIT_MODE": False,
    "PARALLEL_COUNT": 5
}


@dataclass
class DepotDetail:
    """Details about a specific depot"""
    root_listing: str = ""
    unreal_depot: bool = False
    commands_used: List[str] = field(default_factory=list)


@dataclass
class ServerResult:
    """Results from scanning a single server"""
    address: str
    hostname: str
    status: str = "Unknown"
    depots: Optional[str] = None
    changes: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    users_listed: List[str] = field(default_factory=list)
    depot_details: Dict[str, DepotDetail] = field(default_factory=dict)
    triggers_out: Optional[str] = None
    
    def mark_insecure(self, reason: str) -> None:
        """Mark the server as insecure with a specific reason"""
        if not self.status.startswith("Insecure"):
            self.status = "Insecure"
        self.notes.append(reason)


class P4CommandRunner:
    """Handles running p4 commands and processing results"""
    
    @staticmethod
    def run_command(command: str) -> Tuple[str, str, int]:
        """
        Run a shell command and return (stdout, stderr, exit_code).
        This function does NOT do multiple retries.
        """
        print(f"\n[DEBUG] Running command: {command}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10
            )
            # Debug prints
            if result.stdout.strip():
                print("[STDOUT]:")
                print(result.stdout)
            if result.stderr.strip():
                print("[STDERR]:")
                print(result.stderr)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as e:
            print("[ERROR] Command timed out.")
            return "", f"Command timed out: {e}", 1
        except Exception as e:
            print(f"[ERROR] Exception running command: {e}")
            return "", str(e), 1
    
    @staticmethod
    def run_critical_command(command: str) -> Tuple[str, str, int]:
        """
        A wrapper for run_command() that retries once if we get a 'Command timed out'.
        If we time out again, we return a special exit_code 999 (meaning "double timeout").
        """
        stdout, stderr, exit_code = P4CommandRunner.run_command(command)

        if "Command timed out" in stderr:
            # Retry once
            print("[INFO] Retrying command after first timeout...")
            stdout, stderr, exit_code = P4CommandRunner.run_command(command)
            if "Command timed out" in stderr:
                print("[ERROR] Command timed out twice. Bailing out.")
                # Use a unique exit_code to indicate double-timeout
                return stdout, stderr, 999

        return stdout, stderr, exit_code
    
    @staticmethod
    def p4_command(user: str, address: str, cmd: str, password: Optional[str] = None) -> Tuple[str, str, int]:
        """Generate and run a p4 command with given parameters"""
        # Use single quotes around password to prevent shell interpretation of special characters
        pwd_part = f"-P '{password}'" if password else ""
        full_cmd = (f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
                   f"-u {user} -p {address} {pwd_part} {cmd}")
        return P4CommandRunner.run_command(full_cmd)
    
    @staticmethod
    def p4_critical_command(user: str, address: str, cmd: str, password: Optional[str] = None) -> Tuple[str, str, int]:
        """Run a critical p4 command with retry logic"""
        # Use single quotes around password to prevent shell interpretation of special characters
        pwd_part = f"-P '{password}'" if password else ""
        full_cmd = (f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
                   f"-u {user} -p {address} {pwd_part} {cmd}")
        return P4CommandRunner.run_critical_command(full_cmd)


class P4ResponseParser:
    """Parses responses from P4 commands"""
    
    @staticmethod
    def parse_users(output: str) -> List[str]:
        """Parse 'p4 users' output. Return a list of found usernames."""
        pattern = re.compile(r"^(\S+)\s+<([^>]+)>\s+\(([^)]+)\)", re.MULTILINE)
        users = []
        for match in pattern.finditer(output):
            username = match.group(1)
            users.append(username)
        return users
    
    @staticmethod
    def parse_depots(output: str) -> List[str]:
        """Parse 'p4 depots' output to extract depot names."""
        depots = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == "depot":
                # The second token is usually the depot name
                depots.append(parts[1])
        return depots
    
    @staticmethod
    def check_password_required(stdout: str, stderr: str) -> bool:
        """Check if server says 'Password must be set before access can be granted.'"""
        messages = (stdout + stderr).lower()
        return "password must be set before access can be granted." in messages
    
    @staticmethod
    def check_certificate_invalid(stdout: str, stderr: str) -> bool:
        """Check if 'Certificate date range invalid.' is present."""
        return "certificate date range invalid." in (stdout + stderr).lower()
    
    @staticmethod
    def check_user_not_exists(stdout: str, stderr: str) -> bool:
        """Check if user doesn't exist based on the error message"""
        combined = (stdout + stderr).lower()
        return "unknown user" in combined or "doesn't exist" in combined
    
    @staticmethod
    def check_user_not_enabled(stdout: str, stderr: str) -> bool:
        """Check if user is not enabled"""
        combined = (stdout + stderr).lower()
        return "has not been enabled" in combined
    
    @staticmethod
    def check_invalid_password(stdout: str, stderr: str) -> bool:
        """Check if password is invalid but user exists"""
        combined = (stdout + stderr).lower()
        return ("password (p4passwd) invalid or unset" in combined and 
                "user" not in combined and "doesn't exist" not in combined)

class CredentialsManager:
    """Manages known credentials"""
    
    # Class-level lock for thread safety when updating the credentials file
    _lock = threading.Lock()
    
    @staticmethod
    def parse_known_credentials() -> Dict[str, List[Dict[str, str]]]:
        """
        Read known-credentials.txt if it exists.
        Return a dict in this format:
            {
              "ip:port": [
                 {"user": "someUser", "password": "somePass or None"},
                 ...
              ],
              ...
            }
        """
        if not os.path.isfile(CONFIG["KNOWN_CREDS_FILE"]):
            return {}

        with CredentialsManager._lock:  # Use lock when reading to avoid race conditions
            known_creds = {}
            with open(CONFIG["KNOWN_CREDS_FILE"], "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Format: server:port username [password]
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    server_port = parts[0]
                    user = parts[1]
                    password = parts[2] if len(parts) > 2 else None

                    if server_port not in known_creds:
                        known_creds[server_port] = []
                    cred_entry = {"user": user, "password": password}
                    # Only add if it's not already in the list
                    if cred_entry not in known_creds[server_port]:
                        known_creds[server_port].append(cred_entry)

        return known_creds
    
    @staticmethod
    def save_known_credentials(known_creds: Dict[str, List[Dict[str, str]]]) -> None:
        """
        Overwrite known-credentials.txt with the updated contents of known_creds.
        We allow multiple lines per server:port if multiple user/password combos exist.
        """
        with CredentialsManager._lock:  # Use lock to ensure thread safety
            with open(CONFIG["KNOWN_CREDS_FILE"], "w") as f:
                f.write("# Known Perforce credentials discovered.\n")
                f.write("# Format: server:port username [password]\n\n")
                for server_port, creds_list in known_creds.items():
                    for cdict in creds_list:
                        user = cdict.get("user")
                        password = cdict.get("password")
                        if password:
                            f.write(f"{server_port} {user} {password}\n")
                        else:
                            f.write(f"{server_port} {user}\n")
    
    @staticmethod
    def add_credential(known_creds: Dict[str, List[Dict[str, str]]], 
                      server_port: str, user: str, password: Optional[str]) -> None:
        """Add a new credential to the known_creds dictionary"""
        new_cred = {"user": user, "password": password}
        if server_port not in known_creds:
            known_creds[server_port] = []
        if new_cred not in known_creds[server_port]:
            known_creds[server_port].append(new_cred)
            print(f"[INFO] Added new credential for {server_port}: user='{user}', password='{password or 'None'}'")
        else:
            print(f"[INFO] Credential already exists for {server_port}: user='{user}', password='{password or 'None'}'")

class P4SecurityScanner:
    """Core security scanning functionality"""
    
    def __init__(self):
        self.cmd_runner = P4CommandRunner()
        self.parser = P4ResponseParser()
        self._lock = threading.Lock()


    def try_list_depots(self, user: str, address: str, password: Optional[str] = None, 
                        critical: bool = False) -> Tuple[str, str, int]:
        """Try listing depots with the given user/address/password."""
        if critical:
            return self.cmd_runner.p4_critical_command(user, address, "depots", password)
        else:
            return self.cmd_runner.p4_command(user, address, "depots", password)
    
    def try_list_changes(self, user: str, address: str, password: Optional[str] = None) -> Tuple[str, str, int]:
        """Get the last 10 changes with -t -l."""
        return self.cmd_runner.p4_command(user, address, "changes -m 10 -t -l //...", password)
    
    def try_list_triggers(self, user: str, address: str, password: Optional[str] = None) -> Tuple[str, str, int]:
        """Attempt to list triggers with `p4 triggers -o`."""
        return self.cmd_runner.p4_command(user, address, "triggers -o", password)
    
    def try_list_users(self, user: str, address: str, password: Optional[str] = None) -> Tuple[str, str, int]:
        """Try to list users with `p4 users`."""
        return self.cmd_runner.p4_command(user, address, "users", password)
    
    def list_depot_root_dirs(self, user: str, address: str, password: Optional[str], 
                           depot_name: str) -> Tuple[str, str, int]:
        """
        List the root-level directories of a given depot using `p4 dirs //depot_name/*`.
        Return (command_used, combined_output, return_code).
        """
        cmd = f"dirs //{depot_name}/*"
        stdout, stderr, code = self.cmd_runner.p4_command(user, address, cmd, password)
        combined = stdout + stderr
        return cmd, combined, code
    
    def search_unreal_files(self, user: str, address: str, password: Optional[str], 
                          depot_name: str) -> bool:
        """
        Search for Unreal Engine files in a depot.
        If any are found, returns True, else False.
        """
        patterns = [
            f"//{depot_name}/.../DefaultEngine.ini",
            f"//{depot_name}/.../DefaultGame.ini",
            f"//{depot_name}/.../*.uproject"
        ]
        for pattern in patterns:
            stdout, stderr, code = self.cmd_runner.p4_command(user, address, f"files {pattern}", password)
            if code == 0 and stdout.strip():
                # Found at least one file => it's an Unreal Engine Depot
                return True
        return False
    
    def collect_depot_details(self, server_result: ServerResult, user: str, address: str, 
                             password: Optional[str], depots_out: str) -> None:
        """Collect detailed information about each depot"""
        dnames = self.parser.parse_depots(depots_out)
        for dname in dnames:
            server_result.depot_details[dname] = DepotDetail()
            cmd_dirs, listing, _ = self.list_depot_root_dirs(user, address, password, dname)
            server_result.depot_details[dname].root_listing = listing
            server_result.depot_details[dname].commands_used.append(cmd_dirs)

            is_unreal = self.search_unreal_files(user, address, password, dname)
            server_result.depot_details[dname].unreal_depot = is_unreal
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Get the hostname for an IP via reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    def handle_successful_auth(self, server_result: ServerResult, known_creds: Dict[str, List[Dict[str, str]]], 
                            line: str, user: str, address: str, password: Optional[str], depots_out: str) -> bool:
        """Process a successful authentication and determine if we should continue"""
        # Mark as insecure with appropriate reason
        if password:
            server_result.mark_insecure(f"Insecure via user '{user}' with password '{password}'")
        else:
            server_result.mark_insecure(f"Insecure via user '{user}' (no password)")
        
        # Record depot output
        server_result.depots = depots_out.strip()
        
        # Try to get changes
        changes_out, changes_err, code_changes = self.try_list_changes(user, address, password)
        if code_changes == 0:
            server_result.changes = changes_out.strip()
        
        # Try to get triggers
        trig_out, trig_err, trig_code = self.try_list_triggers(user, address, password)
        if trig_code == 0:
            print(f"WARNING: TRIGGERS ACCESSIBLE! CRITICAL SECURITY FAILURE!")
            server_result.triggers_out = (trig_out + trig_err).strip()
        
        # Collect detailed depot information
        self.collect_depot_details(server_result, user, address, password, depots_out)
        
        # Add to known credentials
        CredentialsManager.add_credential(known_creds, line, user, password)
        
        # Save known credentials immediately - new addition
        print(f"[INFO] Saving updated credentials after finding valid credentials for {user} on {address}")
        CredentialsManager.save_known_credentials(known_creds)
        
        # In non-audit mode, we stop here
        return OPTIONS["AUDIT_MODE"]


    def try_password(self, user: str, address: str, pwd: str) -> Tuple[bool, str, Optional[str], Optional[str]]:
        """
        Test a single password for a given user and server.
        Returns (success, password, depots_out, changes_out)
        """
        print(f"[*] Trying password '{pwd}' for user '{user}' on {address} ...")
        depots_out, depots_err, code_depots = self.try_list_depots(user, address, pwd)
        
        # If we see "Password must be set before access can be granted." skip brute force
        if self.parser.check_password_required(depots_out, depots_err):
            return False, pwd, None, None
        
        # Skip if user doesn't exist
        if self.parser.check_user_not_exists(depots_out, depots_err):
            return False, pwd, None, None
        
        # Skip if user is not enabled
        if self.parser.check_user_not_enabled(depots_out, depots_err):
            return False, pwd, None, None

        if code_depots == 0:
            # We can get depots => insecure
            changes_out, changes_err, code_changes = self.try_list_changes(user, address, pwd)
            if code_changes == 0:
                return True, pwd, depots_out, changes_out
            else:
                return True, pwd, depots_out, None
                
        return False, pwd, None, None

    def try_brute_force(self, user: str, address: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Attempt brute-forcing with top-passwords file.
        Return (True, pwd_found, depots_out, changes_out) on success.
        Otherwise (False, None, None, None).
        """
        if not os.path.isfile(CONFIG["TOP_PASSWORDS_FILE"]):
            print(f"[ERROR] Password file '{CONFIG['TOP_PASSWORDS_FILE']}' not found. Cannot brute force.")
            sys.exit(1)
            return False, None, None, None

        # Read all passwords into a list
        passwords = []
        with open(CONFIG["TOP_PASSWORDS_FILE"], "r") as f:
            for pwd in f:
                pwd = pwd.strip()
                if not pwd:
                    continue
                passwords.append(pwd)
        
        # Skip if no passwords
        if not passwords:
            return False, None, None, None
        
        # Try a quick check first to see if the user exists and requires a password
        # This avoids wasting time on parallel checks for invalid users
        test_pwd = passwords[0] if passwords else "test123"
        depots_out, depots_err, _ = self.try_list_depots(user, address, test_pwd)
        
        # Skip if user doesn't exist
        if self.parser.check_user_not_exists(depots_out, depots_err):
            return False, None, None, None
            
        # Skip if user is not enabled
        if self.parser.check_user_not_enabled(depots_out, depots_err):
            return False, None, None, None
        
        # Skip if password must be set (special case)
        if self.parser.check_password_required(depots_out, depots_err):
            return False, None, None, None
        
        # Use ThreadPoolExecutor for parallel password testing
        parallel_count = OPTIONS["PARALLEL_COUNT"]
        print(f"[*] Starting parallel brute force with {parallel_count} workers for {len(passwords)} passwords...")
        
        # Create a partial function with fixed user and address
        test_func = partial(self.try_password, user, address)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel_count) as executor:
            # Submit all password tests as futures
            future_to_pwd = {executor.submit(test_func, pwd): pwd for pwd in passwords}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_pwd):
                success, pwd, depots_out, changes_out = future.result()
                if success:
                    # Cancel all pending futures once we find a match
                    for f in future_to_pwd:
                        f.cancel()
                    return True, pwd, depots_out, changes_out
        
        return False, None, None, None

    def test_user(self, server_result: ServerResult, known_creds: Dict[str, List[Dict[str, str]]], 
                line: str, address: str, user: str) -> bool:
        """Test a specific user for vulnerabilities"""
        print(f"[INFO] Testing user '{user}' for security issues...")
        
        # First try no password
        depots_out, depots_err, code_depots = self.try_list_depots(user, address, None, critical=True)
        
        # Handle timeout
        if code_depots == 999:
            server_result.status = "Unknown - Connection timed out"
            return False
        
        # Check certificate - immediate skip
        if self.parser.check_certificate_invalid(depots_out, depots_err):
            server_result.status = "Unknown - Certificate date range invalid"
            print(f"[INFO] Certificate date range invalid for {address}. Skipping server.")
            return False
        
        # Check if password must be set
        if self.parser.check_password_required(depots_out, depots_err):
            server_result.mark_insecure(f"User '{user}' => password must be set => skipping entire server")
            return False
        
        # Check for non-existent user
        if self.parser.check_user_not_exists(depots_out, depots_err):
            print(f"[INFO] User '{user}' does not exist.")
            return True  # Continue testing other users
        
        # Check if user is not enabled
        if self.parser.check_user_not_enabled(depots_out, depots_err):
            print(f"[INFO] User '{user}' has not been enabled.")
            return True  # Continue testing other users
        
        # Check if we can access with no password
        if code_depots == 0:
            # We got access with no password!
            continue_testing = self.handle_successful_auth(server_result, known_creds, 
                                                         line, user, address, None, depots_out)
            if not continue_testing:
                return False
        
        # Check if we need to try with password (user exists but password needed)
        combined = depots_out + depots_err
        if "Perforce password (P4PASSWD) invalid or unset." in combined:
            # First try user-as-password
            depots_out2, depots_err2, code_depots2 = self.try_list_depots(user, address, user)
            
            # Check if we got access with username as password
            if code_depots2 == 0:
                continue_testing = self.handle_successful_auth(server_result, known_creds, 
                                                             line, user, address, user, depots_out2)
                if not continue_testing:
                    return False
            
            # Try brute force if enabled
            if OPTIONS["BRUTE_MODE"] and self.parser.check_invalid_password(depots_out, depots_err):
                success, pwd_found, depots_out3, changes_out3 = self.try_brute_force(user, address)
                if success:
                    continue_testing = self.handle_successful_auth(server_result, known_creds, 
                                                                 line, user, address, pwd_found, depots_out3)
                    if not continue_testing:
                        return False
        
        return True  # Continue testing other users
    
    def process_server(self, line: str, known_creds: Dict[str, List[Dict[str, str]]]) -> ServerResult:
        """
        Process a single server, checking security and accessibility.
        'line' is e.g. "10.10.10.1:1666".
        known_creds is our dictionary of known credentials.
        """
        ip, port = line.strip().split(":")
        address = f"{ip}:{port}"
        hostname = self.resolve_hostname(ip) or "Unknown Host"

        server_result = ServerResult(address=address, hostname=hostname)

        print(f"\n=== Processing: {address} ({hostname}) ===")
        
        # 1) First check if server is reachable with p4 info
        info_cmd = f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} -u super -p {address} info"
        stdout, stderr, exit_code = self.cmd_runner.run_critical_command(info_cmd)

        # If we had a double-timeout => skip
        if exit_code == 999:
            server_result.status = "Unknown - Connection timed out"
            return server_result

        # Check for SSL requirement
        ssl_message = "Failed client connect, server using SSL."
        if exit_code == 1 or ssl_message in stderr:
            ssl_address = f"SSL:{ip}:{port}"
            trust_cmd = f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} -u super -p {ssl_address} trust -y"
            self.cmd_runner.run_command(trust_cmd)  # attempt to trust
            print(f"[INFO] Retrying with SSL: {ssl_address}")
            
            # Try info command with SSL
            ssl_info_cmd = f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} -u super -p {ssl_address} info"
            ssl_stdout, ssl_stderr, ssl_exit_code = self.cmd_runner.run_critical_command(ssl_info_cmd)
            
            # Check for certificate error immediately
            if self.parser.check_certificate_invalid(ssl_stdout, ssl_stderr):
                server_result.status = "Unknown - Certificate date range invalid"
                print(f"[INFO] Certificate date range invalid for {ssl_address}. Skipping server.")
                return server_result
            
            # Switch to SSL for all future commands
            address = ssl_address
        
        # 2) Try known credentials first
        if line in known_creds:
            print(f"[INFO] Found known credentials for {line}, trying them first...")
            for cred in known_creds[line]:
                kuser = cred["user"]
                kpass = cred["password"]
                print(f"[INFO] Trying known credential: {kuser}/{kpass or 'NoPass'}")
                
                depots_out, depots_err, code_depots = self.try_list_depots(kuser, address, kpass, critical=True)
                
                # Skip on timeout
                if code_depots == 999:
                    server_result.status = "Unknown - Connection timed out"
                    return server_result
                
                # Skip server if password must be set
                if self.parser.check_password_required(depots_out, depots_err):
                    server_result.mark_insecure(f"User '{kuser}' => password must be set => skipping entire server")
                    return server_result
                
                # If we got access with the known credential
                if code_depots == 0:
                    continue_testing = self.handle_successful_auth(server_result, known_creds, 
                                                                 line, kuser, address, kpass, depots_out)
                    if not continue_testing:
                        return server_result
        
        # 3) Try 'super' user first
        continue_testing = self.test_user(server_result, known_creds, line, address, "super")
        if not continue_testing:
            return server_result
        
        # 4) If super is disabled or we're in audit mode, try to list users
        users_out, users_err, users_code = self.try_list_users("super", address)
        
        found_users = []
        if users_code == 0:
            found_users = self.parser.parse_users(users_out)
            if found_users:
                server_result.users_listed = found_users
                server_result.notes.append(f"Users listing is accessible: {', '.join(found_users)}")
        else:
            print("Getting user listing with fallback users....")
            for test_user in CONFIG["FALLBACK_USERS"]:
                users_out, users_err, users_code = self.try_list_users(test_user, address)
                if users_code == 0:
                    found_users = self.parser.parse_users(users_out)
                    # found_users = [user for user in found_users if user != "assembla"]
                    server_result.users_listed = found_users
                    server_result.notes.append(f"Users listing is accessible via impersonating user {test_user}: {', '.join(found_users)}")
                    break

        # 5) Test all discovered users or fallback users
        users_to_test = found_users if found_users else CONFIG["FALLBACK_USERS"]
        
        for test_user in users_to_test:
            # Skip 'super' as we already tested it
            if test_user == "super" or test_user == "assembla":
                continue
                
            # Test this user
            continue_testing = self.test_user(server_result, known_creds, line, address, test_user)
            if not continue_testing:
                return server_result
        
        # If we got here and didn't find any vulnerabilities, the server is likely secure
        if server_result.status == "Unknown":
            server_result.status = "Secure"
            
        return server_result


class ReportGenerator:
    """Generates security reports"""
    
    @staticmethod
    def write_report(results: List[ServerResult], report_file: str) -> None:
        """Write a detailed security report"""
        with open(report_file, "w") as f:
            f.write("Perforce Security Scan Report\n\n")
            for res in results:
                f.write(f"Server: {res.address} ({res.hostname})\n")
                f.write(f"  Status: {res.status}\n")
                if res.notes:
                    for note in res.notes:
                        f.write(f"  Note: {note}\n")

                # Depots?
                f.write("\n  == Depots ==\n")
                if res.depots:
                    f.write(res.depots + "\n")
                else:
                    f.write("  file listing not available (no successful 'depots' command)\n")

                # Changes?
                if res.changes:
                    f.write("\n  == Last 10 Changes ==\n")
                    f.write(res.changes + "\n")

                # Depot details
                if res.depot_details:
                    f.write("\n  == Depot Details ==\n")
                    for dname, ddict in res.depot_details.items():
                        f.write(f"\n  Depot: {dname}\n")
                        # Root listing
                        root_listing = ddict.root_listing.strip()
                        if root_listing:
                            f.write("    -- Root Directories --\n")
                            f.write("    " + root_listing.replace("\n", "\n    ") + "\n")
                        else:
                            f.write("    (No root listing available)\n")

                        # Unreal detection
                        if ddict.unreal_depot:
                            f.write("    This depot appears to be an **Unreal Engine Depot**.\n")
                        else:
                            f.write("    This depot is a non-Unreal Engine Depot.\n")

                        # Commands used
                        cmds_used = ddict.commands_used
                        if cmds_used:
                            f.write("    Commands used for file listing:\n")
                            for c in cmds_used:
                                f.write(f"      {c}\n")

                # Users
                if res.users_listed:
                    f.write("\n  == Users Listed ==\n")
                    f.write(", ".join(res.users_listed))
                    f.write("\n")

                # Triggers
                if res.triggers_out:
                    f.write("\n  == Triggers (p4 triggers -o) ==\n")
                    f.write(res.triggers_out + "\n")

                f.write("\n" + "-" * 60 + "\n\n")

            # Summary report at the end
            f.write("\n\nSummary Report\n\n")
            for res in results:
                note_str = "; ".join(res.notes) if res.notes else ""
                if note_str:
                    f.write(f"Server: {res.address} - {res.status} - Note: {note_str}\n")
                else:
                    f.write(f"Server: {res.address} - {res.status}\n")



def parse_arguments() -> None:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Perforce Security Scanner")
    parser.add_argument("-brute", action="store_true", help="Enable brute force mode")
    parser.add_argument("-audit", action="store_true", 
                     help="Thorough audit mode: test all users even after finding vulnerabilities")
    parser.add_argument("-parallel", type=int, default=1,
                     help="Number of parallel password attempts (default: 1)")
    args = parser.parse_args()
    
    if args.brute:
        print("WARNING: You are about to enable brute force mode. This can be illegal or violate policies.")
        print("Use only on servers you own or are authorized to test.\n")
        answer = input("Type 'YES' to proceed or anything else to abort: ")
        if answer.strip().upper() == "YES":
            OPTIONS["BRUTE_MODE"] = True
            print("[*] Brute force mode enabled.")
        else:
            print("Brute force mode aborted.")
    
    if args.audit:
        OPTIONS["AUDIT_MODE"] = True
        print("[*] Audit mode enabled. Will test all users even after finding vulnerabilities.")
        
    if args.parallel > 1:
        OPTIONS["PARALLEL_COUNT"] = args.parallel
        print(f"[*] Parallel mode enabled with {args.parallel} workers.")

def main() -> None:
    """Main function"""
    # Parse command-line arguments
    parse_arguments()
    
    # Load known credentials
    known_creds = CredentialsManager.parse_known_credentials()
    
    # Initialize scanner
    scanner = P4SecurityScanner()
    
    # Process each server in the input file
    results = []
    if not os.path.isfile(CONFIG["INPUT_FILE"]):
        print(f"[ERROR] Server list file '{CONFIG['INPUT_FILE']}' does not exist.")
        return

    with open(CONFIG["INPUT_FILE"], "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            result = scanner.process_server(line, known_creds)
            results.append(result)
    
    # Generate report
    ReportGenerator.write_report(results, CONFIG["REPORT_FILE"])
    
    # Save updated credentials
    CredentialsManager.save_known_credentials(known_creds)
    
    print(f"\n[INFO] Report saved to {CONFIG['REPORT_FILE']}")
    print(f"[INFO] Updated known credentials saved to {CONFIG['KNOWN_CREDS_FILE']}")

if __name__ == "__main__":
    main()
