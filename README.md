# netexecspray
wrapper for netexec

# netexecspray

A very small, very simple NetExec (`nxc`) wrapper to spray **one username + password**
across **multiple protocols and targets** without having to type the same command 20 times.


Any one is welcome to improve it 🙂

---

# Features
	•	Spray a single username + password across:
	•	SMB
	•	LDAP
	•	WinRM
	•	RDP
	•	SSH
	•	MSSQL
	•	FTP
	•	VNC
	•	WMI
	•	Supports:
	•	Single target
	•	Target list file
	•	Username file
	•	Validation mode (--validate)
	•	Confirms real access (not just auth)
	•	Smart output:
	•	[ACCESS] → confirmed execution / real access
	•	[VALID] → authentication only
	•	Detects:
	•	Pwn3d! from NetExec automatically
	•	Logging:
	•	Saves full output to timestamped log file

---

Requirements
	•	Python 3
	•	netexec (nxc) installed and in PATH

Optional (for validation)
	•	xfreerdp3 → RDP validation
	•	impacket → MSSQL validation

Tested on Kali Linux.
---------------------
Installation
```bash
git clone https://github.com/I-AlanF90/netexecspray.git
cd netexecspray
chmod +x netexecspray.py
```
---------------------

# Add to PATH

### Recommended (symlink)
```
sudo ln -s /opt/netexecspray/netexecspray.py /usr/local/bin/netexecspray
```
# Usage


### Spray a single protocol
```bash
python3 netexecspray.py smb 192.168.1.10 -u Alan -p 'Sup3rS3cretPass!'
```
### Spray multiple protocols
```bash
netexecspray smb,ldap,winrm,rdp,wmi 192.168.1.10 -u Alan -p 'Password123'
```
### Spray all protocols
```bash
netexecspray all targets.txt -U users.txt -p 'Winter2024!'
```
### Enable validation (recommended)
```bash
netexecspray smb,ldap,winrm,rdp,wmi 192.168.1.10 -u Alan -p 'Password123' --validate
```
### Only show confirmed access
```bash
netexecspray all targets.txt -U users.txt -p 'Password123' --validate --only-access
```

# Tips
	•	[ACCESS] = you can likely execute commands / move laterally
	•	[VALID] = creds are good, but access is restricted
	•	LDAP → use for BloodHound
	•	RDP → may be blocked by policy
	•	WMI → may lack execution rights


<img width="1258" height="1090" alt="image" src="https://github.com/user-attachments/assets/144c58e3-b26e-4a55-ab32-75d69abb95ff" />

