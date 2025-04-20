
As part of a cleaning routine, I found a file named svchost.exe in the downloads folder. This particular binary caught my eye for a good reason... Usually this file it does not belong to the donwload folder. As a reminder, Service Host (svchost.exe) is a shared-service process that serves as a shell for loading services from DLL files. Services are organized into related host groups, and each group runs inside a different instance of the Service Host process. svchost.exe can be found in C:\Windows\System32\, so this was the first indicator.
Next, I used PowerShell to look for files named svchost.exe that do not contain System32 in the output.
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Message -like "*svchost.exe*" -and $_.Message -notlike "*System32*" }
```
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
So, as I suspected, a process with this name was created outside of C:\Windows\System32.

Another quick check was to compare the MD5 hash of the suspicious file with the original Windows file. As we can see, the files are not the same...
```plaintext
PS C:\WINDOWS\system32> CertUtil -hashfile "C:\Users\Ignacio\Downloads\svchost.exe" MD5
MD5 hash of C:\Users\Ignacio\Downloads\svchost.exe:
684b2d79bdb1a66058f690e6b480f8c0
```
```plaintext
PS C:\WINDOWS\system32> CertUtil -hashfile "C:\Windows\System32\svchost.exe" MD5
MD5 hash of C:\Windows\System32\svchost.exe:
0cd128f416a04c06d50ec56392c25d9f
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
