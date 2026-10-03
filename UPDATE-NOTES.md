# Düzəlişlər (Pervin - Bend 7 & 9)

## Nə dəyişdi
Əvvəlki rule-ların HAMISI səhv index adlarına baxırdı (ona görə heç biri işləmirdi):
- `index=web_docker_logs`  ->  `index=main sourcetype=bestrio:api:json`
- `index=windows`          ->  `index=main sourcetype=WinEventLog:Security`
- Web sahələri düzəldildi:  `uri` -> `path`,  `http_user_agent` -> `user_agent`
- Windows sahələri düzəldildi: `AccountName` -> `Account_Name`, `Computer` -> `ComputerName`, `LogonType` -> `Logon_Type`
- SPL-016 (DDoS) `.yaml` -> `.yml` adına gətirildi və placeholder index düzəldildi
- SPL-017 (yeni user / honeytoken) əlavə edildi

## Rule-ların vəziyyəti
| Status | Rule-lar |
|---|---|
| Hazır işləyir (web) | 01 SQLi, 02 XSS, 03 LFI, 04 CmdInj, 05 BruteForce, 16 DDoS |
| Hazır işləyir (Windows native) | 08 LogCleared, 10 Kerberoasting, 11 DCSync, 12 SchedTask, 15 PtH, 17 NewUser |
| Command-line GPO lazımdır (4688) | 07 PowerShell-enc, 13 Certutil |
| SYSMON qurulmalıdır | 06 LSASS dump, 09 Webshell, 14 Defender disable |

## sync_siem.ps1
- Parol artıq kodda DEYİL -> environment variable kimi verilir.
- Hər rule-a avtomatik EMAIL alert action + trigger (results > 0) qoşulur.

## Çalışdırmaq
```powershell
$env:SPLUNK_USER = "admin"
$env:SPLUNK_PASS = "<yeni-splunk-parolu>"
$env:ALERT_EMAIL = "finalp844@gmail.com"
powershell -ExecutionPolicy Bypass -File scripts\sync_siem.ps1
```
