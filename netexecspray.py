#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path

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

def run_nxc(proto, target, user, password):
    cmd = [
        "nxc",
        proto,
        target,
        "-u", user,
        "-p", password
    ]

    print(f"[+] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)

def load_targets(target):
    if Path(target).is_file():
        return [line.strip() for line in open(target) if line.strip()]
    return [target]

def main():
    parser = argparse.ArgumentParser(
        description="NetExec multi-protocol spray wrapper"
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
        required=True,
        help="Username"
    )
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="Password"
    )

    args = parser.parse_args()

    # Protocol handling
    if args.protocols == "all":
        protocols = ALL_PROTOCOLS
    else:
        protocols = [p.strip() for p in args.protocols.split(",")]
        invalid = set(protocols) - set(ALL_PROTOCOLS)
        if invalid:
            print(f"[-] Invalid protocol(s): {', '.join(invalid)}")
            sys.exit(1)

    targets = load_targets(args.target)

    print(f"[+] User     : {args.user}")
    print(f"[+] Password : {args.password}")
    print(f"[+] Protocols: {', '.join(protocols)}")
    print(f"[+] Targets  : {len(targets)}\n")

    for proto in protocols:
        print(f"[+] === Protocol: {proto} ===")
        for target in targets:
            run_nxc(proto, target, args.user, args.password)

if __name__ == "__main__":
    main()
