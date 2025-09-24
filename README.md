# 🔍 Digital Forensics Case Study – Memory Analysis of WIN7-CFO

## 📌 Project Overview
This project involved investigating a compromised Windows 7 system (WIN7-CFO) that had been infected through a phishing attack.  
The objective was to perform memory forensics on the captured RAM dump and review event logs to identify the attacker’s actions, the malware used, and potential credential compromise.

## 🛠️ Tools & Techniques
- **FTK Imager** – Captured memory dump & extracted registry hives  
- **Volatility 2** – Performed memory analysis (`pslist`, `pstree`, `cmdline`, `cmdscan`, `consoles`, `hivelist`)  
- **Registry Explorer** – Analyzed user activity & registry artifacts  
- **Event Log Explorer** – Built an incident timeline from Windows event logs  
- **VirusTotal** – Verified malicious file hash and confirmed malware behavior  

## 🔑 Key Findings
- **Malicious File Identified:** `Enhancement Tablxslx.exe` (disguised Excel file)
- **Credential Theft:** Wdigest stored plaintext credentials → extracted by attacker using Mimikatz
- **Persistence & Exfiltration:** Attacker used RDP sessions and PowerShell to escalate and steal credentials
- **Phishing Vector:** File was downloaded via phishing email and executed by user `shauser`

## 🗂️ Incident Timeline
| Date & Time (UTC) | Event |
|-------------------|-------|
| Oct 9, 2018 11:11 AM | User logs in & opens Outlook |
| Oct 9, 2018 11:48 AM | Malicious file downloaded & opened (Excel launched) |
| Oct 9, 2018 2:57 PM | PowerShell initiated – Mimikatz installed |
| Oct 9, 2018 2:59 PM | Notepad opened – likely to store stolen credentials |
| Oct 9, 2018 4:02 PM | User logs off |

## 🖼️ Evidence Screenshots
| Evidence | Description |
|----------|-------------|
| ![Case Study Page 1] | Executive summary of the case |
| ![Case Study Page 4] | Volatility `pslist` showing malicious process |
| ![Case Study Page 6] | VirusTotal result confirming malware |
| ![Case Study Page 10] | Incident timeline and key findings |

## 🛡️ Recommendations
- Disable **Wdigest** authentication across all systems  
- Enforce **multi-factor authentication** to mitigate credential theft  
- Deploy **anti-malware solution** and apply regular patch management  
- Conduct **security awareness training** to reduce phishing risk  
- Implement **network monitoring** and SIEM alerts for RDP & PowerShell usage  

## 📂 Files
- `Digital Forensics Case Study.pdf` – Full investigation report  
- `Case Study Screenshot Folder` – Evidence screenshots

