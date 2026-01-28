# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Valdivialuis123/Threat-Hunt-Scenario-tor/blob/main/hreat-hunting-scenario-tor-event-creation.md))

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents Table for Any File that had the string “Tor” in it and discovered what looks like the user “FinalprojectLab” downloaded a tor Installer, Did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the the desktop. These Events began at
Query used to locate events: 2026-01-27T21:59:15.4399281Z)

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName =="finalprojectlab"
| where  InitiatingProcessAccountName contains "finalprojectlab"
| where Timestamp >= datetime(2026-01-27T21:59:15.4399281Z)
| where FileName contains "tor"
|order by Timestamp desc
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName

```
<img width="1112" height="131" alt="image" src="https://github.com/user-attachments/assets/71075d7c-1f80-40b8-b969-efad69d43612" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents Table for  table that contained the string “tor-browser-windows-x86_64-portable-15.0.4.exe  /S “ Based on the logs returned 
On the afternoon of 2026-01-27T23:14:27.0285718Z, the user account “finalprojectlab123” on the computer named “finalprojectlab” started running the Tor Browser portable installer (version 15.0.4) from their Downloads folder, and it was launched silently 

**Query used to locate event:**

```kql

DeviceProcessEvents
| where  DeviceName =="finalprojectlab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1390" height="275" alt="image" src="https://github.com/user-attachments/assets/e038697f-ed7b-46cf-a48a-2c1822b0790e" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEventsTable for Any indication that the user “FinalprojectLab” actually opened the tor browser. There was evidence that they did open it at 2026-01-27T23:15:28.9759403Z. There were several other instances of firefox.exe(tor) as well as tor.exe spawned 

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName =="finalprojectlab"
| where FileName has_any ("tor.exe", "firefox.exe"," tor-browser.exe")
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
|order  by Timestamp desc
```
<img width="943" height="740" alt="image" src="https://github.com/user-attachments/assets/39d1f062-f79b-458a-807d-d23dd06f862f" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

 Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known port numbers . At  2026-01-27T23:18:14.1259643Z PM on January 27, 2026, the user account “finalprojectlab123” on the computer named “finalprojectlab” successfully made an outgoing network connection from a process called (c:\users\finalprojectlab123\desktop\tor browser\browser\torbrowser\tor\tor.exe) to a remote server at IP address 81.201.202.101 on port 9001 — which is a port commonly used by Tor network nodes to communicate.There was a few other connections. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName =="finalprojectlab"
|where InitiatingProcessAccountName != "system"
|where InitiatingProcessFileName in ("tor.exe","firefox.exe")
|where RemotePort  in ("9001", "9030", "9040", "9050", "9051", "9150","80","443")
|project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="914" height="172" alt="image" src="https://github.com/user-attachments/assets/31e662f2-7540-4c9e-9b2a-b69402d576ba" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:**: 2026-01-27 21:59:15 UTC
Data Source: DeviceFileEvents
The user FinalprojectLab downloaded a file containing the string “tor”, consistent with a Tor Browser installer.
File activity shows the installer was written to disk and staged for execution.
This represents the initial introduction of Tor software onto the system.
Evidence:
DeviceFileEvents entries with filenames containing “tor
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-01-27 23:14:27 UTC`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`
- Outcome:Tor Browser application successfully installed and ready for use
- Installation resulted in multiple Tor-related files and folders being extracted to the Desktop.


### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-27 23:15:28 UTC
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- The user launched the Tor Browser application.
-Multiple processes spawned, including:tor.exe, firefox.exe (Tor Browser variant)tor-browser.exe
outcome- Process creation confirms active user execution, not just installation.


### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-27 23:18:14 UTC
- **Event:** The Tor process established outbound network connections.
Confirmed connection to:remote IP: 81.201.202.101
Port: 9001 (known Tor relay port) Additional encrypted connections observed over ports 443 and 80.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`
- Conclusion:
Tor successfully established circuits and began routing traffic anonymously.

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
