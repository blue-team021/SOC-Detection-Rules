# SPL-018 (Cobalt Strike) - tehlukesiz test plani (bend 20)

Hecbir real zererli proqram (Cobalt Strike, beacon) ISTIFADE OLUNMUR.
Testler yalniz Cobalt Strike-in Sysmon-da biraxdigi izleri zerersiz yolla tekrarlayir.

## Teleb
- Oz Windows VM-imiz (komandanin serverleri yox)
- Sysmon (pipe event-leri 17/18 aktiv olan konfiqurasiya, mes. olafhartong/sysmon-modular)
- Splunk Universal Forwarder -> index=main, sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"

## Test 1 - CS standart named pipe (Event 17)
PowerShell:
```
$p = [System.IO.Pipes.NamedPipeServerStream]::new("msagent_demo01"); Start-Sleep 10; $p.Dispose()
```
Gozlenen: Sysmon Event 17, PipeName=\msagent_demo01 -> SPL-018 "CS standart named pipe"

## Test 2 - Argumentsiz rundll32 (Event 1)
cmd:
```
rundll32.exe
```
(Hec ne etmir, derhal baglanir.) Gozlenen: Event 1, CommandLine=rundll32.exe -> "Argumentsiz rundll32 (spawnto)"

## Test 3 (istege bagli) - Remote thread (Event 8)
Atomic Red Team T1055 (CreateRemoteThread) testi, yalniz VM-de.

## Yoxlama
Splunk:
```
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=17 PipeName="*msagent_*") OR (EventCode=1 Image="*\\rundll32.exe")
```
1-2 deqiqe sonra Gmail-e "Splunk Alert: SPL-018 - MITRE ATTCK - Cobalt Strike Beacon Behavior" maili gelmelidir.
