# netexecspray
wrapper for netexec

# netexecspray

A very small, very simple NetExec (`nxc`) wrapper to spray **one username + password**
across **multiple protocols and targets** without having to type the same command 20 times.

This was built because:
- I got tired of copy/pasting `nxc smb …`, `nxc winrm …`, `nxc rdp …`
- I am lazy
- I am not that smart, so I automate my own mistakes

If you’re smarter than me, feel free to improve it 🙂

---

## What this does

- Takes **one username**
- Takes **one password**
- Tries them against:
  - SMB
  - LDAP
  - WinRM
  - RDP
  - SSH
  - MSSQL
  - FTP
  - VNC
  - WMI
  - (or all of the above)
- Supports:
  - Single target
  - File with multiple targets

That’s it. No magic. No bypasses. Just automation.

---

## What this does NOT do

- It does **not** bypass lockouts
- It does **not** evade detection
- It does **not** do OPSEC for you
- It does **not** make you the goat

It just saves time.

---

## Requirements

- Python 3
- NetExec (`nxc`) installed and in your PATH

Tested on Kali. Probably works elsewhere. No promises.

---

## Usage

### Spray a single protocol
```bash
python3 netexecspray.py smb 192.168.1.10 -u Alan -p 'Sup3rS3cretPass!'
