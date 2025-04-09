
Redline forensics walkthrough leveraging FireEye Redline, IOC Search Collector, SHA256 hash analysis, Windows event logs, prefetch data, and VirusTotal for endpoint threat hunting.

By Ramyar Daneshgar 


## Task 1 – Introduction

Redline is an endpoint forensics tool by FireEye (now Mandiant). It’s tailored for live response collection**, IOC-based scanning, and malware hunting in Windows environments. It collects both volatile and non-volatile artifacts from the host system.

**Answer:** FireEye

---

## Task 2 – Data Collection

I established a connection to the remote host via RDP (Remote Desktop Protocol). Once inside the Windows VM:

- I attempted to save my Redline analysis in the default `Documents\Analysis` folder but was blocked due to pre-existing files (Redline requires a clean directory).
- I created a new folder via GUI:  
  **`C:\Users\Analyst\Desktop\Analysis`**
- Launched the data collection using:  
  **Tool:** Redline  
  **Command:** `RunRedlineAudit.bat`

This batch script executes the Audit Configuration XML that defines what artifacts (e.g., memory, services, prefetch, network connections) Redline collects. The result is a `.mans` file used later for analysis.

---

## Task 3 – Redline Interface Exploration

Once the `.mans` session was ready, I launched Redline Analysis on my host system:

- From the Redline launcher, I selected “Load Existing Analysis” and browsed to the `.mans` file.
- The interface allowed artifact navigation via the left-hand menu.

To locate the current logged-in user, I navigated to:  
`System Information > User Information`

This view lists SID values, usernames, session types, and login timestamps.

---

## Task 4 – Standard Collector Analysis

In this forensic triage, I analyzed the most suspicious system-level activities first:

### 1. OS Detection:
- `System Information` tab gave me the OS version:  
  **Windows Server 2019 Standard Build 17763**

### 2. Malicious Scheduled Task:
- Navigated to `Scheduled Tasks` tab
- Found `MSOfficeUpdateFa.ke` – a **persistence mechanism** crafted to mimic a Microsoft process

### 3. Message in Task Comment:
- Found attacker message in the “Comment” metadata field:  
  `THM-p3R5IStENCe-m3Chani$m`

### 4. Event ID 546:
- Searched `Event Logs` with keyword:  
  `"THM-Redline-User"`  
  → Located custom **malicious event source** created by the attacker

### 5. Event Message:
- Message included adversary taunt:
  `Someone cracked my password. Now I need to rename my puppy-++-`

### 6–8. File Download & Flag:
- Used `File Download History`
- Located suspicious download of `flag.txt` from:
  → `https://wormhole.app/download-stream/gI9vQtChjyYAmZ8Ody0Au`
- Checked local path:
  → `C:\Program Files (x86)\Windows Mail\SomeMailFolder\flag.txt`
- Viewed file in Notepad:  
  → `THM{600D-C@7cH-My-FR1EnD}`

---

## Task 5 – IOC Search Collector

This task switched from exploratory forensics to **signature-based detection** using IOCs (Indicators of Compromise):

- Loaded Redline and configured a **custom IOC collection** targeting known malware artifacts.
- The `.ioc` file defined:
  - Filename: `psylog.exe`
  - Hashes
  - File path
  - Owner

Located metadata showed:
- True filename: `psylog.exe`
- Masqueraded as: `THM1768.exe`
- Owner: `WIN-2DET5DP0NPT\charles`
- Size: `35400`
- IOC Output Path:
  → `C:\Users\charles\Desktop\Keylogger-IOCSearch\IOCs\keylogger.ioc`

---

## Task 6 – IOC Search Collector Analysis

To validate IOC matches:

- Loaded `.mans` session into Redline
- Clicked **"Create IOC Report"**
- Selected the `.ioc` file created in Task 5
- Viewed matches under **“View Hits”**

From the matched entry:

1. File Path:  
   → `C:\Users\Administrator\AppData\Local\Temp\8eJv8w2id6IqN85dfC.exe`

2. Parent Directory:  
   → `C:\Users\Administrator\AppData\Local\Temp`

3. Owner: `BUILTIN\Administrators`

4. Subsystem: `Windows_CUI` – indicates a command-line executable

5. Device Path: `\Device\HarddiskVolume2`

6. SHA256 Hash:  
   → `57492d33b7c0755bb411b22d2dfdfdf088cbbfcd010e30dd8d425d5fe66adff4`

7. Masqueraded Filename (after checking hash in VirusTotal):  
   → `psexec.exe`

---

### 🔧 Tools/Commands Used:
- IOC Report Generator in Redline
- View Hits module
- VirusTotal (to identify malware family using hash)
- IOC Editor

---

## Task 7 – Endpoint Investigation

Using a separate `.mans` session from another Redline analysis:

1. **OS Product Name:**  
   → `Windows 7 Home Basic` (Found in System Information)

2. **Ransom Note File:**  
   Browsed `File System > Desktop > charles`  
   → `_R_E_A_D___T_H_I_S___AJYG1O_.txt`

3. **Defender DLL:**  
   Searched in `Services` tab  
   → `MpSvc.dll`

4. **Downloaded ZIP File:**  
   Filtered for download type = Manual  
   → `eb5489216d4361f9e3650e6a6332f7ee21b0bc9f3f3a4018c69733949be1d481.zip`

5. **Dropped Executable:**  
   Located `.exe` file on Desktop  
   → `Endermanch@Cerber5.exe`

6. **MD5 Hash of Malicious File:**  
   Retrieved from Timeline  
   → `fe1bc60a95b2c2d77cd5d232296a7fa4`

7. **Ransomware Family (from VT hash scan):**  
   → `Cerber`


---

## Final Tool Summary

| Tool/Platform           | Use Case |
|-------------------------|----------|
| **Redline (FireEye)**   | Memory + Disk artifact collection, IOC scanning, local analysis |
| **RDP**                 | Access to compromised VM |
| **VirusTotal**          | Hash lookup and malware family identification |
| **Windows Notepad**     | Manual flag review |
| **Windows File Explorer** | Navigation and file access |
| **IOC Editor**          | Custom indicator creation |
| **Redline Timeline View** | Chronological execution analysis |
| **Event Viewer in Redline** | Log inspection for anomalies |
****

Certainly. Here’s a **precise, bullet-pointed Lessons Learned** section summarizing the key technical takeaways from the Redline walkthrough:

---

## Lessons Learned

- Redline enforces saving to an empty folder; understanding this avoids script execution errors during evidence collection.
- Standard Collector provides a baseline snapshot of system state, ideal for broad triage before diving into IOC-level detail.
- `.mans` files enable offline, repeatable forensic analysis with full access to memory, process, file, and log artifacts.
- System Information and User Information tabs help quickly attribute system activity to specific user sessions.
- Malicious scheduled tasks often mimic legitimate Windows services; anomalies in naming or task behavior are key indicators of persistence.
- Custom Event Log sources like "THM-Redline-User" suggest elevated attacker privileges and intentional footprinting.
- File Download History enables correlation between network activity and dropped payloads—critical in tracing initial access or exfiltration.
- IOC Search Collector allows for targeted hunting using hashes, filenames, paths, and ownership metadata—effective for known malware.
- VirusTotal integration helps validate IOC hits and uncover masqueraded binaries like PsExec or Cerber ransomware.
- Timeline view reveals execution sequence, supporting full attack chain reconstruction from delivery to payload execution.
- Multiple Redline sessions can be used to compare infected endpoints, verify propagation, and refine containment strategy.
- Hashing and reputation checks are fast, accurate ways to classify files when reverse engineering is not feasible.


