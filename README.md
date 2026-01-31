# netexecspray
wrapper for netexec

# netexecspray

A very small, very simple NetExec (`nxc`) wrapper to spray **one username + password**
across **multiple protocols and targets** without having to type the same command 20 times.

This was built because:
- I got tired of copy/pasting `nxc smb …`, `nxc winrm …`, `nxc rdp …`
- I am lazy
- It's perfect for HTB, OSCP prep.

Any one is welcome to improve it 🙂

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


---

## What this does NOT do

- It does **not** bypass lockouts, so be careful spraying. 
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
```

<img width="773" height="837" alt="netexecspary" src="https://github.com/user-attachments/assets/9fb5e8d1-aedc-448c-aca8-1c5a20636069" />


