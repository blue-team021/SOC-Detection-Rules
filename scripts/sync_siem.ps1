# ============================================================
#  SOC-Detection-Rules -> Splunk sync (via REST API)
#  Bend 9: rules are authored in GitHub, pushed to Splunk by API.
#
#  SECURITY: credentials are NOT stored in this file.
#  Set them as environment variables before running:
#      $env:SPLUNK_USER = "admin"
#      $env:SPLUNK_PASS = "<your-splunk-password>"
#      $env:ALERT_EMAIL = "finalp844@gmail.com"
#  Then run:  powershell -ExecutionPolicy Bypass -File scripts\sync_siem.ps1
# ============================================================

$SplunkHost = "13.53.133.248"
$SplunkPort = "8089"
$User  = $env:SPLUNK_USER
$Pass  = $env:SPLUNK_PASS
$Email = if ($env:ALERT_EMAIL) { $env:ALERT_EMAIL } else { "finalp844@gmail.com" }

if (-not $User -or -not $Pass) {
    Write-Host "[-] Set SPLUNK_USER and SPLUNK_PASS environment variables first." -ForegroundColor Red
    exit 1
}

$Uri  = "https://$SplunkHost`:$SplunkPort/servicesNS/nobody/search/saved/searches"
$Auth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$User`:$Pass"))
$Headers = @{ Authorization = "Basic $Auth" }

Get-ChildItem "rules\splunk" -Filter "*.yml" | ForEach-Object {
    $c = Get-Content $_.FullName -Raw
    $id     = ($c | Select-String 'id:\s*"(.*?)"').Matches.Groups[1].Value
    $name   = ($c | Select-String 'name:\s*"(.*?)"').Matches.Groups[1].Value
    $search = ($c | Select-String 'search:\s*>\s*([\s\S]*?)\Z').Matches.Groups[1].Value.Trim()
    $full   = "$id - $name"

    # Full alert config: scheduled, trigger on results>0, email action
    $body = @{
        "search"                            = $search
        "is_scheduled"                      = "1"
        "cron_schedule"                     = "*/5 * * * *"
        "dispatch.earliest_time"            = "-15m"
        "dispatch.latest_time"              = "now"
        "alert_type"                        = "number of results"
        "alert_comparator"                  = "greater than"
        "alert_threshold"                   = "0"
        "alert.track"                       = "1"
        "alert.suppress"                    = "1"
        "alert.suppress.period"             = "1h"
        "actions"                           = "email"
        "action.email"                      = "1"
        "action.email.to"                   = $Email
        "action.email.subject"              = "Splunk Alert: $full"
        "action.email.include.results_link" = "1"
        "action.email.format"               = "table"
    }

    try {
        # Try to CREATE (needs name)
        $create = $body.Clone(); $create["name"] = $full
        Invoke-RestMethod -Uri $Uri -Method Post -Headers $Headers -Body $create -SkipCertificateCheck | Out-Null
        Write-Host "[+] Created: $full" -ForegroundColor Green
    } catch {
        try {
            # Already exists -> UPDATE (name goes in the URL, not the body)
            $enc = [uri]::EscapeDataString($full)
            Invoke-RestMethod -Uri "$Uri/$enc" -Method Post -Headers $Headers -Body $body -SkipCertificateCheck | Out-Null
            Write-Host "[~] Updated: $full" -ForegroundColor Yellow
        } catch {
            Write-Host "[-] Failed: $full -> $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
