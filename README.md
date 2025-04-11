# Sysmon Blue Team Lab 🛡️

This repository serves as a **laboratory** to showcase my skills in **security monitoring** using **Sysmon** on Windows systems. In this lab, I will walk you through the installation of Sysmon, configuring it using the recommended **SwiftOnSecurity's Sysmon Config**, and performing basic analysis to detect suspicious activities.

---

## **Table of Contents** 📚

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Step 1: Download and Install Sysmon](#step-1-download-and-install-sysmon)
- [Step 2: Configure Sysmon](#step-2-configure-sysmon)
- [Step 3: Analyze Sysmon Logs](#step-3-analyze-sysmon-logs)
- [Contributing](#contributing)

---

## **Introduction** 🎯

**Sysmon** (System Monitor) is a powerful Windows system service and device driver developed by Microsoft’s Sysinternals suite. It provides detailed information about system activity, which can be used for detecting malicious behavior, performing incident response, and creating a comprehensive security monitoring setup.

In this lab, we will be setting up Sysmon with the configuration file recommended by **SwiftOnSecurity** to monitor various system events such as process creations, network connections, file modifications, and registry changes. This configuration helps to identify suspicious or anomalous activities that might indicate a cyber attack.

---

## **Prerequisites** ⚙️

Before proceeding, ensure you have the following:

- **Windows OS** (Windows 10 or Server 2016 and above)
- **Sysmon** (downloadable from the Sysinternals suite)
- **SwiftOnSecurity's Sysmon Config**: This is the configuration file we will use, which is designed for security monitoring.
- Administrator privileges 🔑
- Basic understanding of cybersecurity and security monitoring principles 🔍

---

## **Step 1: Download and Install Sysmon** 📥

Follow these steps to download and install Sysmon:

1. **Download Sysmon** from the official [Sysinternals website](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. **Extract** the downloaded zip file to a location on your machine.
3. **Open PowerShell as Administrator** and navigate to the Sysmon folder.
---

## Step 2: Configure Sysmon Using SwiftOnSecurity's Sysmon Config ⚙️

The SwiftOnSecurity GitHub repository provides a community-vetted sysmonconfig.xml that’s designed to monitor key system activities like process creation, network connections, file changes, and registry modifications. This configuration is ideal for detecting malicious activities on Windows systems.

Visit the official SwiftOnSecurity Sysmon Config repository: https://github.com/SwiftOnSecurity/sysmon-config

Download the latest sysmonconfig.xml file from the repository and save it in your Sysmon folder (where you extracted Sysmon).

The following command will install the system, with the configuration file
```powershell
    sysmon -accepteula -i sysmonconfig-export.xml
```
After installation, verify that Sysmon is running by checking the Event Viewer for Sysmon logs:
```powershell
    Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```
You should see events for process creation, network connections, and other monitored activities.

## Step 3: Detecting a Fake svchost.exe Process 🕵️‍♂️

In this step, we simulate a scenario where a malicious actor attempts to disguise a malicious process as the legitimate svchost.exe, which is a common technique used in malware campaigns.
🔬 Simulation:

We use a Python script that copies cmd.exe, renames it to svchost.exe, and executes it from a user-controlled directory like Downloads.
🧪 Execution:
```powershell
python svchost.py
```
This will create a fake process named svchost.exe and run it for a few seconds.
🔎 Sysmon Detection:

Open Event Viewer and navigate to:
```nginx
Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```
Then, filter for:

. Event ID 1 – Process Creation

. Image: Should not be running from C:\Windows\System32

. Parent Process: Typically, real svchost.exe is started by services.exe, not python.exe

Example Red Flags:
```plaintext
Image: C:\Users\Username\Downloads\svchost.exe
ParentImage: C:\Python311\python.exe
CommandLine: "C:\Users\Username\Downloads\svchost.exe"
```
This is a strong indicator of process masquerading and can be used to detect malware that attempts to blend in with system processes.

📸 See screenshots of the detection in the [images/](./images/) folder.  
📄 Full analysis available in: [suspicious_activity_analysis.md](./suspicious_activity_analysis.md)

