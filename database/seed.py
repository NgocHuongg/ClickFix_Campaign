"""
Seed generator for the SOC Simulation database.

Builds a deterministic data set:
  * 20 alerts (SOC325 .. SOC344), each linked to a small, sanitized scenario in the logs
  * ~3900 log events (scenario events + background noise from many hosts / log sources)
  * endpoints, threat-intel IOCs, e-mails, sandbox reports and a couple of cases

Scenario content is intentionally generic (placeholder file names, documentation-range
IPs, redacted parameters) - it models the *shape* of SOC telemetry for training, not
working attack material.

Usage:  python database/seed.py [path/to/soc.db]
"""
from __future__ import annotations

import hashlib
import json
import random
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DB = HERE / "soc.db"
SCHEMA = HERE / "schema.sql"
TS_FMT = "%Y-%m-%d %H:%M:%S"
TARGET_LOG_COUNT = 3907
NOISE_START = datetime(2025, 1, 1, 0, 0, 0)
NOISE_END = datetime(2025, 9, 26, 16, 55, 0)

rnd = random.Random(1337)


# --------------------------------------------------------------------------- helpers
def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest().upper()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest().upper()


def ts(s: str) -> datetime:
    return datetime.strptime(s, TS_FMT)


def fmt(d: datetime) -> str:
    return d.strftime(TS_FMT)


def utc(d: datetime) -> str:
    """Platform time is UTC+3; Sysmon-style UtcTime field."""
    return (d - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S.") + f"{rnd.randint(0, 999):03d}"


def eph() -> int:
    return rnd.randint(49152, 65535)


# --------------------------------------------------------------------------- endpoints
# hostname, ip, os, user, domain
ENDPOINTS = [
    ("EC2AMAZ-ILGVOIN", "172.16.20.69", "Windows Server 2019", "SOCUser", "EC2AMAZ-ILGVOIN"),
    ("Joseph-PC", "172.16.17.45", "Windows 10 Enterprise", "joseph", "CORP"),
    ("SharePoint01", "172.16.20.17", "Windows Server 2019", "spadmin", "CORP"),
    ("DevOps-Linux01", "172.16.20.33", "Ubuntu 22.04 LTS", "devops", "-"),
    ("Tomcat-Web01", "172.16.20.25", "Ubuntu 20.04 LTS", "tomcat", "-"),
    ("Emily-PC", "172.16.17.61", "Windows 11 Pro", "emily", "CORP"),
    ("Mark-PC", "172.16.17.88", "Windows 10 Enterprise", "mark", "CORP"),
    ("Sarah-PC", "172.16.17.102", "Windows 11 Pro", "sarah", "CORP"),
    ("Kevin-PC", "172.16.17.120", "Windows 10 Enterprise", "kevin", "CORP"),
    ("Anna-PC", "172.16.17.133", "Windows 11 Pro", "anna", "CORP"),
    ("WebServer-01", "172.16.20.10", "Ubuntu 22.04 LTS", "www-data", "-"),
    ("DC01", "172.16.20.3", "Windows Server 2022", "Administrator", "CORP"),
    ("Tom-PC", "172.16.17.150", "Windows 10 Enterprise", "tom", "CORP"),
    ("Linda-PC", "172.16.17.171", "Windows 11 Pro", "linda", "CORP"),
    ("FileServer01", "172.16.20.40", "Windows Server 2022", "svc_backup", "CORP"),
]
EP = {e[0]: e for e in ENDPOINTS}
WIN = [e[0] for e in ENDPOINTS if e[2].startswith("Windows")]
LNX = [e[0] for e in ENDPOINTS if not e[2].startswith("Windows")]
WEB_SERVERS = ["WebServer-01", "Tomcat-Web01", "SharePoint01"]

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
EXPLORER = "C:\\Windows\\explorer.exe"


def is_win(host: str) -> bool:
    return EP[host][2].startswith("Windows")


def user_of(host: str) -> str:
    h = EP[host]
    return f"{h[4]}\\{h[3]}" if h[4] != "-" else h[3]


# --------------------------------------------------------------------------- log builders
LOGS: list[tuple] = []


def add(t, typ, src, sport, dst, dport, host, user, proc, cmd, action, raw):
    LOGS.append((fmt(t), typ, src, sport, dst, dport, host, user, proc, cmd, action, raw))


def os_proc(t, host, image, cmd, parent=EXPLORER, user=None):
    ip = EP[host][1]
    user = user or user_of(host)
    pid = rnd.randint(1000, 9999)
    if is_win(host):
        raw = (f"User: {user}, Image: {image}, Hashes: MD5={md5(image)},SHA256={sha256(image)}, "
               f"CommandLine: {cmd}, ParentImage: {parent}, UtcTime: {utc(t)}, RuleName: -, "
               f"ProcessId: {pid}, EventID: 1")
    else:
        raw = (f"type=EXECVE host={host} user={user} exe=\"{image}\" cmdline=\"{cmd}\" "
               f"pid={pid} parent=\"{parent}\"")
    add(t, "OS", ip, None, ip, None, host, user, image, cmd, "Executed", raw)


def os_event(t, host, text, image=None, user=None, action="Info"):
    ip = EP[host][1]
    raw = f"UtcTime: {utc(t)}, {text}"
    add(t, "OS", ip, None, ip, None, host, user or user_of(host), image, None, action, raw)


def net(t, host, dst, dport, image, action="Allowed", proto="TCP"):
    ip = EP[host][1]
    user = user_of(host)
    sport = eph()
    raw = (f"User: {user}, Image: {image}, UtcTime: {utc(t)}, RuleName: -, Protocol: {proto}, "
           f"SourceIp: {ip}, SourcePort: {sport}, DestinationIp: {dst}, DestinationPort: {dport}, "
           f"Action: {action}, EventID: 3")
    add(t, "Network", ip, sport, dst, dport, host, user, image, None, action, raw)


def firewall(t, src, dst, dport, action, proto="TCP", rule="default"):
    sport = eph()
    raw = (f"device=FW-EDGE-01 action={action.lower()} proto={proto} src={src} spt={sport} "
           f"dst={dst} dpt={dport} rule=\"{rule}\" bytes={rnd.randint(60, 90000)}")
    add(t, "Firewall", src, sport, dst, dport, None, None, None, None, action, raw)


UA_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"


def proxy(t, host, url, dst, method="GET", status=200, action="Allowed", ua=UA_WIN):
    ip = EP[host][1]
    sport = eph()
    raw = (f"Method: {method}, URL: {url}, Status: {status}, Action: {action}, SourceIp: {ip}, "
           f"DestinationIp: {dst}, User: {user_of(host)}, UserAgent: {ua}, "
           f"BytesIn: {rnd.randint(300, 900000)}, BytesOut: {rnd.randint(200, 4000)}")
    add(t, "Proxy", ip, sport, dst, 443 if url.startswith("https") else 80, host, user_of(host),
        None, None, action, raw)


def dns(t, host, domain, answer):
    ip = EP[host][1]
    raw = f"Query: {domain}, QueryType: A, Response: {answer}, Client: {ip}, Server: 172.16.20.3"
    add(t, "DNS", ip, eph(), "172.16.20.3", 53, host, None, None, None, "Resolved", raw)


def web(t, src, host, method, uri, status, ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0", action="Allowed"):
    port = {"SharePoint01": 443, "Tomcat-Web01": 8080}.get(host, 80)
    stamp = t.strftime("%d/%b/%Y:%H:%M:%S +0300")
    raw = f'{src} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} {rnd.randint(200, 25000)} "-" "{ua}"'
    add(t, "Web", src, eph(), EP[host][1], port, host, None, None, None, action, raw)


def auth(t, src, host, user, success, logon_type=3):
    eid = 4624 if success else 4625
    msg = "An account was successfully logged on" if success else "An account failed to log on"
    raw = (f"EventID: {eid}, Message: {msg}, TargetUserName: {user}, WorkstationName: {host}, "
           f"LogonType: {logon_type}, SourceNetworkAddress: {src}")
    add(t, "Authentication", src, eph(), EP[host][1], 3389 if logon_type == 10 else 445, host, user,
        None, None, "Success" if success else "Failure", raw)


# --------------------------------------------------------------------------- scenarios
# Attacker / C2 infrastructure uses documentation ranges (RFC 5737) and .example domains.
ALERTS: list[dict] = []


def alert(event_id, rule, severity, typ, when, details, status="main", owner=None, verdict=None, note=None):
    ALERTS.append(dict(event_id=event_id, rule_name=rule, severity=severity, type=typ, created_at=when,
                       details=details, status=status, owner=owner, verdict=verdict, close_note=note))


def endpoint_malware_scenario(host, t0, sample, delivery_url, c2_ip, c2_domain, trigger):
    """Generic chain: download -> execution -> child process -> C2 beacon."""
    t = ts(t0)
    u = EP[host][3]
    path = f"C:\\Users\\{u}\\Downloads\\{sample}"
    dns(t, host, c2_domain, c2_ip)
    proxy(t + timedelta(seconds=2), host, delivery_url, c2_ip)
    os_proc(t + timedelta(minutes=1), host, path, f"\"{path}\"")
    os_proc(t + timedelta(minutes=1, seconds=3), host, CMD, "cmd.exe /c <redacted>", parent=path)
    os_event(t + timedelta(minutes=1, seconds=5), host,
             f"Image: {path}, TargetFilename: C:\\Users\\{u}\\AppData\\Local\\Temp\\stage2.tmp, EventID: 11 (FileCreate)",
             image=path, action="Detected")
    for i in range(3):
        net(t + timedelta(minutes=2 + i), host, c2_ip, 443, path)
    return {
        "Hostname": host, "IP Address": EP[host][1], "Username": user_of(host),
        "File Name": sample, "File Path": path, "File Hash (SHA256)": sha256(path),
        "C2 Address": f"{c2_domain} ({c2_ip})", "Trigger Reason": trigger, "Device Action": "Allowed",
    }


def web_attack_scenario(host, t0, attacker, n, trigger, marker):
    """Generic web attack: burst of anomalous requests from a single external source."""
    t = ts(t0)
    for i in range(n):
        st = rnd.choice([200, 403, 404, 500])
        web(t + timedelta(seconds=i * 7), attacker, host, rnd.choice(["GET", "POST"]),
            f"/app/endpoint?id={i}&payload=<{marker}-redacted>", st, ua="python-requests/2.31")
    firewall(t, attacker, EP[host][1], {"SharePoint01": 443, "Tomcat-Web01": 8080}.get(host, 80),
             "Allowed", rule="inbound-web")
    return {
        "Hostname": host, "Destination IP": EP[host][1], "Source IP": attacker,
        "Request Count": n, "User Agent": "python-requests/2.31",
        "Trigger Reason": trigger, "Device Action": "Allowed",
    }


def build_scenarios():
    # ---- SOC344 : matches the screenshot timeline on EC2AMAZ-ILGVOIN
    host = "EC2AMAZ-ILGVOIN"
    edr = "C:\\Users\\SOCUser\\Downloads\\EDR-Freeze_1.0.exe"
    wer = "C:\\Windows\\System32\\WerFaultSecure.exe"
    dns(ts("2025-09-26 16:58:40"), host, "github.com", "140.82.113.4")
    for s in ("17:01:30", "17:02:34", "17:02:56"):
        os_proc(ts(f"2025-09-26 {s}"), host, PS, "powershell.exe -nop <redacted>")
    net(ts("2025-09-26 17:01:30"), host, "140.82.113.4", 443, PS)
    net(ts("2025-09-26 17:01:30"), host, "185.199.111.133", 443, PS)
    os_proc(ts("2025-09-26 17:03:28"), host, edr, f"\"{edr}\" <pid> <ms>", parent=PS)
    os_proc(ts("2025-09-26 17:03:28"), host, wer, f"{wer} <args redacted>", parent=edr)
    os_event(ts("2025-09-26 17:03:32"), host,
             f"RuleName: -, SourceUser: NT AUTHORITY\\SYSTEM, TargetUser: {user_of(host)}, NewThreadId: 6300, "
             f"SourceImage: {wer}, TargetImage: C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe, "
             "EventID: 8 (CreateRemoteThread)", image=wer, user="NT AUTHORITY\\SYSTEM", action="Detected")
    alert(322, "SOC344 - EDR Tampering Attempt via EDR-Freeze", "High", "Malware", "2025-09-26 17:26:44", {
        "Hostname": host, "IP Address": EP[host][1], "Username": user_of(host), "Process": edr,
        "Parent Process": PS, "File Hash (SHA256)": sha256(edr),
        "Trigger Reason": "Unsigned binary spawned WerFaultSecure.exe targeting the AV service process",
        "Device Action": "Allowed"})

    alert(321, "SOC343 - WinRAR Zero-Day Path Traversal Vulnerability (CVE-2025-8088)", "Critical", "Malware",
          "2025-08-15 08:31:00", endpoint_malware_scenario(
              "Joseph-PC", "2025-08-15 08:24:10", "Invoice_Aug2025.rar",
              "https://files.bad-share.example/Invoice_Aug2025.rar", "203.0.113.19", "files.bad-share.example",
              "Archive extraction wrote a file outside the target folder (Startup directory)"))

    alert(320, "SOC342 - CVE-2025-53770 SharePoint ToolShell Auth Bypass and RCE", "Critical", "Web Attack",
          "2025-07-22 13:07:10", web_attack_scenario(
              "SharePoint01", "2025-07-22 13:04:00", "198.51.100.76", 14,
              "Unauthenticated requests to a vulnerable SharePoint endpoint followed by w3wp.exe child process",
              "sp-exploit"))
    os_proc(ts("2025-07-22 13:06:58"), "SharePoint01", PS, "powershell.exe -enc <redacted>",
            parent="C:\\Windows\\System32\\inetsrv\\w3wp.exe")

    h = "DevOps-Linux01"
    os_proc(ts("2025-07-04 08:08:41"), h, "/usr/bin/sudo", "sudo -R <redacted> /bin/sh", parent="/bin/bash", user="devops")
    os_event(ts("2025-07-04 08:09:02"), h, "type=USER_ROLE_CHANGE uid=1001 new_uid=0 exe=/usr/bin/sudo res=success",
             image="/usr/bin/sudo", user="devops", action="Detected")
    alert(319, "SOC341 - Local Privilege Escalation via chroot CVE-2025-32463", "High", "Privilege Escalation",
          "2025-07-04 08:10:00", {"Hostname": h, "IP Address": EP[h][1], "Username": "devops",
                                  "Process": "/usr/bin/sudo", "Trigger Reason": "sudo invoked with chroot option by a non-privileged user, followed by uid 0 shell",
                                  "Device Action": "Allowed"})

    alert(318, "SOC340 - Apache Tomcat Serialized Payload RCE (CVE-2025-24813)", "Critical", "Web Attack",
          "2025-05-30 18:19:29", web_attack_scenario(
              "Tomcat-Web01", "2025-05-30 18:16:00", "198.51.100.23", 9,
              "Partial PUT with serialized session object followed by GET with forged session cookie",
              "tomcat-deser"))

    alert(317, "SOC339 - ZDI-CAN-25373 Windows Shortcut Exploit Detected", "High", "Malware",
          "2025-03-20 13:48:20", endpoint_malware_scenario(
              "Emily-PC", "2025-03-20 13:40:00", "Project_Brief.lnk",
              "https://cdn.docs-view.example/Project_Brief.zip", "203.0.113.45", "cdn.docs-view.example",
              "LNK file with padded, hidden command-line arguments launched a script interpreter"))

    alert(316, "SOC338 - Lumma Stealer - DLL Side-Loading via Click Fix Phishing", "Critical", "Data Leakage",
          "2025-03-13 09:44:00", endpoint_malware_scenario(
              "Mark-PC", "2025-03-13 09:35:00", "setup_verify.exe",
              "https://verify-human.example/check", "203.0.113.88", "verify-human.example",
              "Run-dialog command from fake CAPTCHA page loaded unsigned DLL via side-loading; browser data exfiltrated"))

    alert(315, "SOC337 - Lazarus Phishing Campaign Detected (APT38)", "High", "APT Group",
          "2025-03-06 07:15:00", endpoint_malware_scenario(
              "Sarah-PC", "2025-03-06 07:02:00", "Job_Offer_Details.docx",
              "https://careers-portal.example/offer", "192.0.2.61", "careers-portal.example",
              "Attachment from phishing e-mail spawned child process and contacted known APT infrastructure"))

    alert(314, "SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)", "Critical", "Malware",
          "2025-02-04 16:18:08", endpoint_malware_scenario(
              "Kevin-PC", "2025-02-04 16:10:00", "Meeting_Notes.rtf",
              "https://mail-attach.example/Meeting_Notes.rtf", "192.0.2.14", "mail-attach.example",
              "Outlook previewed an RTF file which spawned an unexpected child process"))

    h = "Anna-PC"
    os_proc(ts("2025-01-22 02:35:10"), h, "C:\\Users\\anna\\AppData\\Local\\Temp\\clfs_test.exe", "clfs_test.exe",
            parent=EXPLORER)
    os_event(ts("2025-01-22 02:36:40"), h, "Image: C:\\Users\\anna\\AppData\\Local\\Temp\\clfs_test.exe, "
             "Message: Process token elevated to NT AUTHORITY\\SYSTEM, EventID: 4672", action="Detected")
    alert(313, "SOC335 - CVE-2024-49138 Exploitation Detected", "Medium", "Privilege Escalation",
          "2025-01-22 02:37:00", {"Hostname": h, "IP Address": EP[h][1], "Username": user_of(h),
                                  "Process": "C:\\Users\\anna\\AppData\\Local\\Temp\\clfs_test.exe",
                                  "Trigger Reason": "Unsigned process in Temp obtained SYSTEM token after CLFS driver activity",
                                  "Device Action": "Allowed"})

    # ---- page 2 (older alerts), some already handled
    alert(312, "SOC334 - Suspicious PowerShell Download Cradle", "High", "Malware", "2025-01-15 11:20:12",
          endpoint_malware_scenario("Tom-PC", "2025-01-15 11:12:00", "update_check.ps1",
                                    "https://update-check.example/u.ps1", "192.0.2.201", "update-check.example",
                                    "PowerShell with hidden window downloaded and executed a remote script"))

    h, attacker = "DC01", "198.51.100.140"
    t = ts("2025-01-12 03:10:00")
    for i in range(40):
        auth(t + timedelta(seconds=i * 3), attacker, h, rnd.choice(["administrator", "admin", "backup", "sql"]),
             False, logon_type=10)
    alert(311, "SOC333 - RDP Brute Force Attempt Detected", "Medium", "Brute Force", "2025-01-12 03:12:30",
          {"Hostname": h, "Destination IP": EP[h][1], "Source IP": attacker, "Failed Logons": 40,
           "Trigger Reason": "More than 30 failed RDP logons from one source within 2 minutes", "Device Action": "Blocked"})

    alert(310, "SOC332 - SQL Injection Attempt Detected", "High", "Web Attack", "2025-01-09 14:02:11",
          web_attack_scenario("WebServer-01", "2025-01-09 14:00:00", "198.51.100.9", 18,
                              "SQL meta-characters in query parameters with 500 responses", "sqli"),
          status="investigation", owner="SOC Analyst")

    alert(309, "SOC331 - Phishing URL Clicked", "Medium", "Phishing", "2025-01-07 10:45:00",
          endpoint_malware_scenario("Linda-PC", "2025-01-07 10:40:00", "login.html",
                                    "https://m1crosoft-login.example/auth", "203.0.113.150",
                                    "m1crosoft-login.example", "User clicked a URL from a reported phishing e-mail"))

    h = "FileServer01"
    os_event(ts("2025-01-05 22:14:10"), h, "SourceImage: C:\\Users\\Public\\tool64.exe, TargetImage: "
             "C:\\Windows\\System32\\lsass.exe, GrantedAccess: 0x1010, EventID: 10 (ProcessAccess)", action="Detected")
    alert(308, "SOC330 - LSASS Memory Access by Unknown Process", "High", "Malware", "2025-01-05 22:15:00",
          {"Hostname": h, "IP Address": EP[h][1], "Process": "C:\\Users\\Public\\tool64.exe",
           "Trigger Reason": "Unsigned process opened lsass.exe with memory read rights", "Device Action": "Allowed"},
          status="closed", owner="SOC Analyst", verdict="True Positive",
          note="Credential dumping confirmed. Host isolated, credentials rotated. See case #1.")

    h = "Tom-PC"
    t = ts("2025-01-04 09:00:00")
    for i in range(25):
        sub = f"{rnd.getrandbits(64):016x}.tunnel.example"
        dns(t + timedelta(seconds=i * 5), h, sub, "198.51.100.200")
    alert(307, "SOC329 - Possible DNS Tunneling Detected", "Medium", "Data Leakage", "2025-01-04 09:03:00",
          {"Hostname": h, "IP Address": EP[h][1], "Domain": "tunnel.example",
           "Trigger Reason": "High volume of long, high-entropy subdomain queries to one domain", "Device Action": "Allowed"})

    h = "FileServer01"
    for i in range(12):
        os_event(ts("2025-01-03 01:20:00") + timedelta(seconds=i), h,
                 f"Image: C:\\ProgramData\\svc.exe, TargetFilename: D:\\Shares\\Finance\\report_{i}.xlsx.locked, "
                 "EventID: 11 (FileCreate)", image="C:\\ProgramData\\svc.exe", action="Detected")
    alert(306, "SOC328 - Ransomware File Encryption Behavior", "Critical", "Malware", "2025-01-03 01:21:00",
          {"Hostname": h, "IP Address": EP[h][1], "Process": "C:\\ProgramData\\svc.exe",
           "Trigger Reason": "Mass file rename with new extension on file share", "Device Action": "Blocked"})

    alert(305, "SOC327 - Cross-Site Scripting Attempt", "Low", "Web Attack", "2025-01-02 16:40:00",
          web_attack_scenario("WebServer-01", "2025-01-02 16:38:00", "198.51.100.77", 5,
                              "Script tags in query parameter, responses 403 (WAF)", "xss"),
          status="closed", owner="SOC Analyst", verdict="False Positive",
          note="Internal vulnerability scanner (authorized). Whitelisted source.")

    h = "DC01"
    os_event(ts("2025-01-02 02:10:00"), h, "EventID: 4720, Message: A user account was created, "
             "TargetUserName: svc_helpdesk2, SubjectUserName: CORP\\kevin", action="Detected")
    os_event(ts("2025-01-02 02:10:30"), h, "EventID: 4732, Message: A member was added to a security-enabled "
             "local group, Group: Administrators, Member: svc_helpdesk2", action="Detected")
    alert(304, "SOC326 - Unauthorized Admin Account Created", "Medium", "Privilege Escalation", "2025-01-02 02:11:00",
          {"Hostname": h, "Created Account": "svc_helpdesk2", "Created By": "CORP\\kevin",
           "Trigger Reason": "New account added to Administrators outside change window", "Device Action": "Allowed"},
          status="investigation", owner="SOC Analyst")

    attacker = "198.51.100.5"
    t = ts("2025-01-01 05:00:00")
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 8080]):
        firewall(t + timedelta(seconds=i), attacker, "172.16.20.10", port, "Blocked", rule="inbound-deny")
    alert(303, "SOC325 - Port Scan Detected from External IP", "Low", "Reconnaissance", "2025-01-01 05:01:00",
          {"Source IP": attacker, "Destination IP": "172.16.20.10", "Ports Probed": 16,
           "Trigger Reason": "16 distinct destination ports within 20 seconds", "Device Action": "Blocked"},
          status="closed", owner="SOC Analyst", verdict="True Positive", note="Blocked at perimeter, no follow-up activity.")


# --------------------------------------------------------------------------- background noise
BENIGN_SITES = [
    ("www.google.com", "142.250.185.68"), ("outlook.office365.com", "52.97.146.162"),
    ("teams.microsoft.com", "52.113.194.132"), ("github.com", "140.82.113.4"),
    ("www.wikipedia.org", "185.15.59.224"), ("slack.com", "3.94.170.12"),
    ("update.microsoft.com", "13.107.4.50"), ("www.linkedin.com", "13.107.42.14"),
    ("stackoverflow.com", "151.101.1.69"), ("docs.python.org", "151.101.0.223"),
]
WIN_PROCS = [
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer"),
    ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe --no-startup-window"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "OUTLOOK.EXE /recycle"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "EXCEL.EXE /dde"),
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p"),
    ("C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe"),
    ("C:\\Windows\\System32\\notepad.exe", "notepad.exe"),
    ("C:\\Windows\\System32\\SearchIndexer.exe", "SearchIndexer.exe /Embedding"),
    (PS, "powershell.exe -c Get-Service"),
    (CMD, "cmd.exe /c ipconfig /all"),
]
LNX_PROCS = [("/usr/sbin/sshd", "sshd -D"), ("/usr/bin/apt", "apt update"), ("/usr/sbin/cron", "cron -f"),
             ("/usr/bin/python3", "python3 /opt/app/worker.py"), ("/usr/sbin/nginx", "nginx: worker process")]
WEB_URIS = ["/", "/index.html", "/login", "/api/v1/products", "/static/app.js", "/static/style.css",
            "/images/logo.png", "/about", "/contact", "/api/v1/cart"]
EXTERNAL_CLIENTS = [f"198.51.100.{i}" for i in range(100, 130)] + [f"203.0.113.{i}" for i in range(200, 230)]


def rand_time() -> datetime:
    span = int((NOISE_END - NOISE_START).total_seconds())
    return NOISE_START + timedelta(seconds=rnd.randint(0, span))


def build_noise(n: int):
    for _ in range(n):
        t = rand_time()
        kind = rnd.choices(["os", "net", "proxy", "dns", "web", "fw", "auth"], [30, 12, 18, 14, 12, 9, 5])[0]
        if kind == "os":
            host = rnd.choice(WIN + LNX)
            img, cmd = rnd.choice(WIN_PROCS if is_win(host) else LNX_PROCS)
            os_proc(t, host, img, cmd, parent=EXPLORER if is_win(host) else "/sbin/init")
        elif kind == "net":
            host = rnd.choice(WIN)
            dom, ip = rnd.choice(BENIGN_SITES)
            net(t, host, ip, 443, rnd.choice(WIN_PROCS[:4])[0])
        elif kind == "proxy":
            host = rnd.choice(WIN)
            dom, ip = rnd.choice(BENIGN_SITES)
            proxy(t, host, f"https://{dom}/", ip, status=rnd.choice([200, 200, 200, 301, 304, 404]))
        elif kind == "dns":
            host = rnd.choice(WIN + LNX)
            dom, ip = rnd.choice(BENIGN_SITES)
            dns(t, host, dom, ip)
        elif kind == "web":
            web(t, rnd.choice(EXTERNAL_CLIENTS), rnd.choice(WEB_SERVERS), rnd.choice(["GET", "GET", "POST"]),
                rnd.choice(WEB_URIS), rnd.choice([200, 200, 200, 304, 404]))
        elif kind == "fw":
            src = rnd.choice(EXTERNAL_CLIENTS)
            firewall(t, src, rnd.choice(["172.16.20.10", "172.16.20.25", "172.16.20.17"]),
                     rnd.choice([80, 443, 22, 3389]), rnd.choice(["Allowed", "Allowed", "Blocked"]))
        else:
            host = rnd.choice(WIN)
            auth(t, rnd.choice([e[1] for e in ENDPOINTS]), host, EP[host][3], rnd.random() > 0.08)


# --------------------------------------------------------------------------- reference data
def build_iocs():
    rows = [
        ("ip", "203.0.113.19", "AbuseFeed", "malware,c2", "Archive exploit dropper", 90),
        ("domain", "files.bad-share.example", "AbuseFeed", "malware-delivery", "Archive exploit dropper", 85),
        ("ip", "198.51.100.76", "InternalIntel", "scanner,exploit", "SharePoint exploitation", 95),
        ("ip", "198.51.100.23", "InternalIntel", "exploit", "Tomcat exploitation", 80),
        ("domain", "cdn.docs-view.example", "OpenCTI", "lnk,apt", "LNK campaign", 75),
        ("domain", "verify-human.example", "URLFeed", "clickfix,stealer", "Lumma Stealer", 92),
        ("ip", "203.0.113.88", "URLFeed", "stealer,c2", "Lumma Stealer", 90),
        ("domain", "careers-portal.example", "OpenCTI", "apt,phishing", "Lazarus Group", 88),
        ("ip", "192.0.2.61", "OpenCTI", "apt,c2", "Lazarus Group", 88),
        ("domain", "mail-attach.example", "AbuseFeed", "phishing", "OLE exploit delivery", 70),
        ("ip", "198.51.100.140", "Honeypot", "bruteforce,rdp", "RDP brute force", 65),
        ("domain", "tunnel.example", "InternalIntel", "dns-tunnel,exfil", "DNS tunneling", 80),
        ("domain", "m1crosoft-login.example", "URLFeed", "phishing,credential", "Credential phishing", 95),
        ("url", "https://m1crosoft-login.example/auth", "URLFeed", "phishing", "Credential phishing", 95),
        ("ip", "198.51.100.5", "Honeypot", "scanner", "Mass scanning", 50),
        ("sha256", sha256("C:\\Users\\SOCUser\\Downloads\\EDR-Freeze_1.0.exe"), "SandboxFeed", "edr-tamper",
         "EDR-Freeze", 85),
        ("md5", md5("C:\\ProgramData\\svc.exe"), "SandboxFeed", "ransomware", "Ransomware", 97),
    ]
    out = []
    for i, r in enumerate(rows):
        out.append(r + (fmt(ts("2024-12-01 00:00:00") + timedelta(days=i * 13)),))
    return out


def build_emails():
    mails = [
        ("2025-09-25 09:12:00", "it-support@helpdesk-portal.example", "socuser@corp.local",
         "Security tool update required", "203.0.113.7",
         "Hello,\n\nPlease install the attached security update before end of day.\n\nIT Support",
         [{"name": "update_tool.zip", "size": 184320, "md5": md5("update_tool.zip")}], "Allowed"),
        ("2025-08-15 08:20:00", "billing@invoices-now.example", "joseph@corp.local", "Invoice August 2025",
         "203.0.113.19", "Dear Joseph,\n\nPlease find the invoice at the link below.\n\nRegards",
         [], "Allowed"),
        ("2025-03-06 06:55:00", "recruiter@careers-portal.example", "sarah@corp.local",
         "Exciting opportunity - Senior Engineer", "192.0.2.61",
         "Hi Sarah,\n\nWe were impressed with your profile. Details of the offer are attached.",
         [{"name": "Job_Offer_Details.docx", "size": 98304, "md5": md5("Job_Offer_Details.docx")}], "Allowed"),
        ("2025-03-13 09:30:00", "no-reply@verify-human.example", "mark@corp.local", "Action required: verify account",
         "203.0.113.88", "Your account needs verification. Click the link and follow the instructions.", [], "Allowed"),
        ("2025-02-04 16:05:00", "hr@mail-attach.example", "kevin@corp.local", "Meeting notes",
         "192.0.2.14", "Hi Kevin, notes from today's meeting attached.",
         [{"name": "Meeting_Notes.rtf", "size": 45056, "md5": md5("Meeting_Notes.rtf")}], "Allowed"),
        ("2025-01-07 10:35:00", "security@m1crosoft-login.example", "linda@corp.local",
         "Unusual sign-in activity", "203.0.113.150",
         "We detected an unusual sign-in. Review your activity immediately.", [], "Allowed"),
        ("2025-01-06 08:00:00", "newsletter@vendor.example", "all@corp.local", "Monthly product newsletter",
         "192.0.2.90", "Here are this month's product updates.", [], "Allowed"),
        ("2025-01-05 13:22:00", "promo@cheap-deals.example", "tom@corp.local", "You WON a gift card!!!",
         "198.51.100.66", "Claim your gift card now.", [], "Blocked"),
        ("2025-02-18 11:10:00", "ceo@corp-lcoal.example", "finance@corp.local", "Urgent wire transfer",
         "198.51.100.91", "Please process the wire transfer today, I'm in a meeting.", [], "Quarantined"),
        ("2025-04-02 15:45:00", "colleague@corp.local", "anna@corp.local", "Q2 planning", "172.16.20.5",
         "Hi Anna, see the Q2 plan attached.",
         [{"name": "Q2_plan.xlsx", "size": 22528, "md5": md5("Q2_plan.xlsx")}], "Allowed"),
    ]
    return [(m[0], m[1], m[2], m[3], m[4], m[5], json.dumps(m[6]), m[7]) for m in mails]


def build_sandbox():
    def rep(procs, nets, mitre, sigs):
        return json.dumps({"processes": procs, "network": nets, "mitre": mitre, "signatures": sigs})

    edr = "C:\\Users\\SOCUser\\Downloads\\EDR-Freeze_1.0.exe"
    return [
        ("EDR-Freeze_1.0.exe", sha256(edr), md5(edr), "PE32+ executable", "Malicious", 86, "2025-09-26 17:30:00",
         rep(["EDR-Freeze_1.0.exe", "WerFaultSecure.exe"], [],
             ["T1562.001 Impair Defenses: Disable or Modify Tools"],
             ["Spawns WerFaultSecure.exe with suspicious arguments", "Suspends protected process"])),
        ("Invoice_Aug2025.rar", sha256("Invoice_Aug2025.rar"), md5("Invoice_Aug2025.rar"), "RAR archive",
         "Malicious", 92, "2025-08-15 08:40:00",
         rep(["WinRAR.exe", "cmd.exe", "powershell.exe"], ["203.0.113.19:443"],
             ["T1204.002 User Execution: Malicious File", "T1547.001 Registry Run Keys / Startup Folder"],
             ["Writes file to Startup folder", "Archive contains alternate data streams"])),
        ("Job_Offer_Details.docx", sha256("Job_Offer_Details.docx"), md5("Job_Offer_Details.docx"),
         "Microsoft Word 2007+", "Malicious", 78, "2025-03-06 07:30:00",
         rep(["WINWORD.EXE", "cmd.exe"], ["192.0.2.61:443"], ["T1566.001 Spearphishing Attachment"],
             ["Office document spawns command shell", "Contacts known APT infrastructure"])),
        ("setup_verify.exe", sha256("setup_verify.exe"), md5("setup_verify.exe"), "PE32 executable",
         "Malicious", 95, "2025-03-13 10:00:00",
         rep(["setup_verify.exe", "rundll32.exe"], ["203.0.113.88:443"],
             ["T1574.002 DLL Side-Loading", "T1555.003 Credentials from Web Browsers"],
             ["Reads browser credential stores", "Loads unsigned DLL from application directory"])),
        ("Q2_plan.xlsx", sha256("Q2_plan.xlsx"), md5("Q2_plan.xlsx"), "Microsoft Excel 2007+", "Clean", 3,
         "2025-04-02 16:00:00", rep(["EXCEL.EXE"], [], [], [])),
        ("update_tool.zip", sha256("update_tool.zip"), md5("update_tool.zip"), "ZIP archive", "Suspicious", 55,
         "2025-09-25 09:40:00", rep(["explorer.exe"], [], ["T1036 Masquerading"],
                                    ["Archive contains executable with double extension"])),
    ]


def build_cases(alert_ids: dict[int, int]):
    return [
        (alert_ids[308], "LSASS credential dumping on FileServer01", "High", "Closed", "True Positive",
         "SOC Analyst", "Unsigned tool accessed LSASS memory. Host contained, credentials rotated.",
         "2025-01-05 22:30:00", "2025-01-06 10:00:00"),
        (alert_ids[310], "SQL injection attempts against WebServer-01", "High", "In Progress", None,
         "SOC Analyst", "Investigating whether any injected request returned data.",
         "2025-01-09 14:20:00", "2025-01-09 15:05:00"),
    ]


# --------------------------------------------------------------------------- main
def seed(db_path: Path = DEFAULT_DB) -> None:
    if db_path.exists():
        db_path.unlink()
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA.read_text(encoding="utf-8"))

    build_scenarios()
    build_noise(TARGET_LOG_COUNT - len(LOGS))
    LOGS.sort(key=lambda r: r[0])
    con.executemany(
        "INSERT INTO logs(timestamp,type,source_address,source_port,destination_address,destination_port,"
        "hostname,username,process,command_line,action,raw_log) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", LOGS)

    alert_ids = {}
    for a in sorted(ALERTS, key=lambda a: a["created_at"]):
        closed_at = a["created_at"] if a["status"] == "closed" else None
        cur = con.execute(
            "INSERT INTO alerts(event_id,severity,created_at,rule_name,type,status,owner,verdict,close_note,"
            "closed_at,details) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (a["event_id"], a["severity"], a["created_at"], a["rule_name"], a["type"], a["status"], a["owner"],
             a["verdict"], a["close_note"], closed_at, json.dumps(a["details"])))
        alert_ids[a["event_id"]] = cur.lastrowid

    for hn, ip, os_, user, dom in ENDPOINTS:
        last = con.execute("SELECT MAX(timestamp) FROM logs WHERE hostname=?", (hn,)).fetchone()[0]
        history = [{"time": fmt(rand_time()), "url": f"https://{rnd.choice(BENIGN_SITES)[0]}/"} for _ in range(6)]
        history.sort(key=lambda h: h["time"], reverse=True)
        con.execute("INSERT INTO endpoints(hostname,ip_address,os,primary_user,domain,last_seen,browser_history) "
                    "VALUES (?,?,?,?,?,?,?)", (hn, ip, os_, user, dom, last, json.dumps(history)))
    con.execute("UPDATE endpoints SET contained=1 WHERE hostname='FileServer01'")

    con.executemany("INSERT INTO iocs(ioc_type,value,source,tags,threat,confidence,first_seen) "
                    "VALUES (?,?,?,?,?,?,?)", build_iocs())
    con.executemany("INSERT INTO emails(received_at,sender,recipient,subject,smtp_ip,body,attachments,action) "
                    "VALUES (?,?,?,?,?,?,?,?)", build_emails())
    con.executemany("INSERT INTO sandbox_reports(file_name,sha256,md5,file_type,verdict,score,submitted_at,report) "
                    "VALUES (?,?,?,?,?,?,?,?)", build_sandbox())
    for c in build_cases(alert_ids):
        cur = con.execute("INSERT INTO cases(alert_id,title,severity,status,verdict,assignee,description,"
                          "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)", c)
        con.execute("INSERT INTO case_notes(case_id,author,body,created_at) VALUES (?,?,?,?)",
                    (cur.lastrowid, "SOC Analyst", "Case opened from alert.", c[7]))
    con.commit()
    n_logs = con.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    con.close()
    print(f"Seeded {db_path} : {len(ALERTS)} alerts, {n_logs} logs, {len(ENDPOINTS)} endpoints")


if __name__ == "__main__":
    seed(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DB)
