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

```powershell
PS C:\WINDOWS\system32> CertUtil -hashfile "C:\Users\Ignacio\Downloads\svchost.exe" MD5
MD5 hash of C:\Users\Ignacio\Downloads\svchost.exe:
684b2d79bdb1a66058f690e6b480f8c0
```
```powershell
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
