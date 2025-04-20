## 🔍 Detection
As part of a routine system check, I discovered a file named svchost.exe located in the Downloads folder. This immediately raised a red flag. Normally, this executable should not reside in that location.

![Screenshot 2025-04-20 143946](https://github.com/user-attachments/assets/53f2b47a-fa7f-486b-abba-945a273f300e)


As a reminder, Service Host (svchost.exe) is a critical system process in Windows that acts as a generic host for services running from DLL files. These services are grouped by function and run in separate instances of the Service Host process. The legitimate svchost.exe is typically located in C:\Windows\System32\, so finding it elsewhere is a strong indicator of compromise (IoC).

To investigate further, I used PowerShell to query Sysmon logs and search for any svchost.exe executions occurring outside of the expected directory:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Message -like "*svchost.exe*" -and $_.Message -notlike "*System32*" }
```
This query returned several events involving the creation and termination of a process named svchost.exe, which, notably, did not originate from the System32 directory:
```plaintext
ProviderName: Microsoft-Windows-Sysmon

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
11/04/2025 16:15:44               5 Information      Process terminated:...
11/04/2025 16:15:34               1 Information      Process Create:...
11/04/2025 16:15:34              11 Information      File created:...
11/04/2025 16:15:01               5 Information      Process terminated:...
11/04/2025 16:14:51               1 Information      Process Create:...
11/04/2025 16:14:50              11 Information      File created:...
```
This confirmed that a suspicious instance of svchost.exe had been executed outside of its legitimate path.

## File Metadata Analysis
The metadata of the suspicious file also provided valuable insight. By examining the creation date and time of the file, I was able to correlate it with the Sysmon event logs. The file creation timestamp matched the time frame when the suspicious process was initiated, reinforcing the suspicion that this might be an unauthorized or malicious process.

<a href="https://github.com/user-attachments/assets/bf8f07d2-4d7b-4d0e-b292-f350bf1ab3e8" target="_blank">
  <img src="https://github.com/user-attachments/assets/bf8f07d2-4d7b-4d0e-b292-f350bf1ab3e8" alt="Screenshot svchost suspicious" width="400"/>
</a>

Based on the creation date and time of the suspicious svchost.exe file, I narrowed down my search within Event Viewer (specifically the Sysmon logs). This allowed me to focus on a precise time window and correlate relevant events more effectively.

During this time frame, multiple Process Create (Event ID 1) and File Creation (Event ID 11) events were recorded, all related to the svchost.exe located in the Downloads folder.

Upon further inspection of these logs, it became evident that the image path and the parent process were inconsistent with what we would expect from a legitimate svchost.exe execution. Additionally, neither the process itself nor its parent were digitally signed by Microsoft, which further increased the suspicion.

<a href="https://github.com/user-attachments/assets/4f38ccaf-6c38-413e-aced-06ea04bc95ee" target="_blank">
  <img src="https://github.com/user-attachments/assets/4f38ccaf-6c38-413e-aced-06ea04bc95ee" alt="Screenshot1" width="400"/>
</a>


## sha256 Hash Comparison
As an additional verification step, I compared the sha256 hash of the suspicious file with that of the legitimate svchost.exe. The mismatch in hashes confirmed they were not the same binary:
```plaintext
PS C:\WINDOWS\system32> CertUtil -hashfile C:\Users\Ignacio\Downloads\svchost.exe sha256
SHA256 hash of C:\Users\Ignacio\Downloads\svchost.exe:
6eef334d826be3dc737bb30fbe84b69e529aab956ec33d714b5a75276a58ed04
```
```plaintext
PS C:\WINDOWS\system32> CertUtil -hashfile C:\Windows\System32\svchost.exe sha256
SHA256 hash of C:\Windows\System32\svchost.exe:
324451797ac909a4dd40c7a2f7347ef91f6b7c786941ad5035f609c0fc15edaa
```
```powershell

```
```powershell

```
```powershell

```
```powershell

```
```powershell

```
```powershell

```
