# SOC-Detection-Rules -> Splunk sync (REST API) | PowerShell 5.1 uyğun
# Işlətmək (repo qovluğunun içində):
#   $env:SPLUNK_PASS = "parolun"
#   powershell -ExecutionPolicy Bypass -File scripts\sync_siem.ps1
# Hər rule üçün: Splunk-da id-si (SPL-001...) eyni olan alert varsa UPDATE edir, yoxdursa CREATE edir.

if (-not ("TrustAllCertsPolicy" -as [type])) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$SplunkHost = "13.53.133.248"; $SplunkPort = "8089"
$User  = if ($env:SPLUNK_USER) { $env:SPLUNK_USER } else { "millisec" }
$Pass  = $env:SPLUNK_PASS
$Email = if ($env:ALERT_EMAIL) { $env:ALERT_EMAIL } else { "finalp844@gmail.com" }
if (-not $Pass) { Write-Host "[-] Evvelce yaz: `$env:SPLUNK_PASS = 'parolun'" -ForegroundColor Red; exit 1 }

$Base = "https://$SplunkHost`:$SplunkPort"
$Uri  = "$Base/servicesNS/$User/search/saved/searches"
$Auth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$User`:$Pass"))
$Headers = @{ Authorization = "Basic $Auth" }

function Get-ErrDetail($e) {
    $txt = ""
    if ($e.ErrorDetails -and $e.ErrorDetails.Message) { $txt = $e.ErrorDetails.Message }
    elseif ($e.Exception.Response) {
        try {
            $sr = New-Object System.IO.StreamReader($e.Exception.Response.GetResponseStream())
            $txt = $sr.ReadToEnd()
        } catch { }
    }
    if (-not $txt) { $txt = $e.Exception.Message }
    $m = [regex]::Match($txt, '<msg[^>]*>(.*?)</msg>')            # Splunk-un real xeta mesaji
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($txt, '"text"\s*:\s*"(.*?)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return $txt
}

Write-Host "`n>>> Splunk-a '$User' kimi qosulurum ($SplunkHost)...`n" -ForegroundColor Cyan

# 1) Splunk-da movcud alert-leri oxu: id (SPL-001) -> {ad, link}
$existing = @{}
try {
    $list = Invoke-RestMethod -Uri "${Uri}?output_mode=json&count=0" -Method Get -Headers $Headers
    foreach ($en in $list.entry) {
        $m = [regex]::Match($en.name, '^(SPL-\d+)')
        if ($m.Success) { $existing[$m.Groups[1].Value] = $en }
    }
    Write-Host "[i] Splunk-da movcud SPL alert sayi: $($existing.Count)" -ForegroundColor Cyan
} catch {
    Write-Host "[-] Splunk-a qosulmaq/oxumaq alinmadi:" -ForegroundColor Red
    Write-Host "    $(Get-ErrDetail $_)" -ForegroundColor DarkGray
    exit 1
}

$ok = 0; $fail = 0

Get-ChildItem "rules\splunk" -Filter "*.yml" | Sort-Object Name | ForEach-Object {
    $c      = Get-Content $_.FullName -Raw
    $id     = [regex]::Match($c, '(?m)^id:\s*"?([^"\r\n]+?)"?\s*$').Groups[1].Value
    $name   = [regex]::Match($c, '(?m)^name:\s*"?([^"\r\n]+?)"?\s*$').Groups[1].Value
    $search = [regex]::Match($c, '(?m)^search:\s*>\s*\r?\n([\s\S]+)').Groups[1].Value
    $search = ($search -replace '\s+', ' ').Trim()

    if (-not $id -or -not $search) {
        Write-Host "[-] Skip (id/search oxunmadi): $($_.Name)" -ForegroundColor Red
        $fail++; return
    }

    # Ad: yalniz herf/reqem/bosluq/tire (xususi simvollar URL-i pozur)
    $safeName = ($name -replace '[^\w \-]', '').Trim()
    $full     = "$id - $safeName"

    $body = [ordered]@{
        "search"               = $search
        "is_scheduled"         = "1"
        "cron_schedule"        = "*/5 * * * *"
        "dispatch.earliest_time" = "-15m"
        "dispatch.latest_time" = "now"
        "alert_type"           = "number of events"
        "alert_comparator"     = "greater than"
        "alert_threshold"      = "0"
        "alert.track"          = "1"
        "alert.suppress"       = "1"
        "alert.suppress.period" = "3600s"
        "actions"              = "email"
        "action.email.to"      = $Email
        "action.email.subject" = "Splunk Alert: $full"
        "action.email.sendresults" = "1"
    }

    try {
        if ($existing.ContainsKey($id)) {
            $link = $existing[$id].links.alternate          # Splunk-un oz verdiyi dogru link
            Invoke-RestMethod -Uri "$Base$link" -Method Post -Headers $Headers -Body $body | Out-Null
            Write-Host "[~] Updated: $full" -ForegroundColor Yellow
        } else {
            $create = [ordered]@{ "name" = $full }
            foreach ($k in $body.Keys) { $create[$k] = $body[$k] }
            Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $create | Out-Null
            Write-Host "[+] Created: $full" -ForegroundColor Green
        }
        $ok++
    } catch {
        Write-Host "[-] Failed: $full" -ForegroundColor Red
        Write-Host "    SEBEB: $(Get-ErrDetail $_)" -ForegroundColor DarkGray
        $fail++
    }
}

Write-Host "`n>>> Netice: $ok ugurlu, $fail ugursuz`n" -ForegroundColor Cyan
