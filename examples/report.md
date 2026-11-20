# Network scan report: scan-2026-11-15.xml

- Scan date: 2026-11-15 02:00 UTC
- Command: `nmap -sV -T4 -oX scan.xml 192.168.10.0/24`
- Hosts up: **7**, open ports: **20**
- Risks: **2 critical**, 5 high, 2 medium, 8 low

## Changes since previous scan

| Change | Host | Port | Service |
|---|---|---|---|
| new host | 192.168.10.60 (build01.office.lan) | 22/tcp, 2375/tcp | |
| host gone | 192.168.10.50 (printer.office.lan) | | |
| **port opened** | 192.168.10.20 (db01.office.lan) | 6379/tcp | redis Redis key-value store 7.0.15 |
| port closed | 192.168.10.40 (acct-pc.office.lan) | 3389/tcp | ms-wbt-server |
| service changed | 192.168.10.10 | 80/tcp | http nginx 1.18.0 (Ubuntu) -> http nginx 1.24.0 (Ubuntu) |
| service changed | 192.168.10.10 | 443/tcp | http nginx 1.18.0 -> http nginx 1.24.0 |

## Risks

| Severity | Host | Port | Finding | Why it matters | Fix |
|---|---|---|---|---|---|
| critical | 192.168.10.20 (db01.office.lan) | 6379/tcp | Redis exposed | Redis has no authentication by default and is routinely wiped or used for RCE. | Bind to 127.0.0.1, set requirepass / ACLs, firewall the port. |
| critical | 192.168.10.60 (build01.office.lan) | 2375/tcp | Docker API exposed | Anyone who reaches the Docker API gets root on the host. | Never expose 2375/2376. Use SSH or a VPN to manage Docker. |
| high | 192.168.10.20 (db01.office.lan) | 3306/tcp | Database port exposed | Databases should only be reachable from the application servers. Exposed ones are brute-forced constantly. | Firewall the port to known IPs or move it to a private network / SSH tunnel. |
| high | 192.168.10.30 (nvr.office.lan) | 8000/tcp | Hikvision SDK / service port exposed | Port 8000 on Hikvision DVR/NVR/cameras is targeted by botnets and known auth-bypass bugs. | Do not port-forward CCTV devices. Use the vendor P2P service or a VPN, update firmware. |
| high | 192.168.10.31 | 37777/tcp | Dahua DVR service port exposed | Port 37777 on Dahua devices has a long history of authentication bypass vulnerabilities. | Close the port-forward, use a VPN, update firmware. |
| high | 192.168.10.40 (acct-pc.office.lan) | 139/tcp | SMB / NetBIOS exposed | SMB on the internet invites worms (WannaCry) and credential attacks. | Block 139/445 at the edge. |
| high | 192.168.10.40 (acct-pc.office.lan) | 445/tcp | SMB / NetBIOS exposed | SMB on the internet invites worms (WannaCry) and credential attacks. | Block 139/445 at the edge. |
| medium | 192.168.10.30 (nvr.office.lan) | 554/tcp | RTSP video stream exposed | Camera streams are often viewable without a password. | Require authentication on RTSP and do not expose 554 to the internet. |
| medium | 192.168.10.40 (acct-pc.office.lan) | 135/tcp | MS RPC exposed | RPC endpoint mapper leaks information about Windows hosts. | Block 135 at the edge. |
| low | 192.168.10.1 (gw.office.lan) | 22/tcp | SSH exposed | Expected on servers, but it will be brute-forced. | Use keys only, disable root login, add fail2ban. See linux-hardening-audit. |
| low | 192.168.10.1 (gw.office.lan) | 80/tcp | Plain HTTP service | Traffic and logins on this port are not encrypted. | Redirect to HTTPS (see web-sec-check). |
| low | 192.168.10.10 (web01.office.lan) | 22/tcp | SSH exposed | Expected on servers, but it will be brute-forced. | Use keys only, disable root login, add fail2ban. See linux-hardening-audit. |
| low | 192.168.10.10 (web01.office.lan) | 80/tcp | Plain HTTP service | Traffic and logins on this port are not encrypted. | Redirect to HTTPS (see web-sec-check). |
| low | 192.168.10.20 (db01.office.lan) | 22/tcp | SSH exposed | Expected on servers, but it will be brute-forced. | Use keys only, disable root login, add fail2ban. See linux-hardening-audit. |
| low | 192.168.10.30 (nvr.office.lan) | 80/tcp | Plain HTTP service | Traffic and logins on this port are not encrypted. | Redirect to HTTPS (see web-sec-check). |
| low | 192.168.10.31 | 80/tcp | Plain HTTP service | Traffic and logins on this port are not encrypted. | Redirect to HTTPS (see web-sec-check). |
| low | 192.168.10.60 (build01.office.lan) | 22/tcp | SSH exposed | Expected on servers, but it will be brute-forced. | Use keys only, disable root login, add fail2ban. See linux-hardening-audit. |

## Hosts

### 192.168.10.1 (gw.office.lan)

| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | Dropbear sshd 2022.83 |
| 53/tcp | domain | dnsmasq 2.89 |
| 80/tcp | http | lighttpd |
| 443/tcp | https | lighttpd |

### 192.168.10.10 (web01.office.lan)

| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0) |
| 80/tcp | http | nginx 1.24.0 (Ubuntu) |
| 443/tcp | http | nginx 1.24.0 |

### 192.168.10.20 (db01.office.lan)

| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0) |
| 3306/tcp | mysql | MySQL 8.0.36-0ubuntu0.22.04.1 |
| 6379/tcp | redis | Redis key-value store 7.0.15 |

### 192.168.10.30 (nvr.office.lan)

| Port | Service | Version |
|---|---|---|
| 80/tcp | http | Hikvision IP camera httpd |
| 554/tcp | rtsp | Hikvision 7513 POE IP camera rtspd |
| 8000/tcp | http-alt | Hikvision DVR SDK |

### 192.168.10.31

| Port | Service | Version |
|---|---|---|
| 80/tcp | http | Dahua DVR httpd |
| 37777/tcp | unknown | Dahua DVR |

### 192.168.10.40 (acct-pc.office.lan)

| Port | Service | Version |
|---|---|---|
| 135/tcp | msrpc | Microsoft Windows RPC |
| 139/tcp | netbios-ssn | Microsoft Windows netbios-ssn |
| 445/tcp | microsoft-ds |  |

### 192.168.10.60 (build01.office.lan)

| Port | Service | Version |
|---|---|---|
| 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0) |
| 2375/tcp | docker | Docker 26.1.3 (API 1.45) |
