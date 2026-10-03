# Bitdefender GravityZone XDR -> Splunk (index=xdr) | PowerShell 5.1 compatible
#
# 1) Tests Splunk HEC directly (event goes to index=xdr)
# 2) Configures GravityZone Event Push Service -> Splunk HEC (setPushEventSettings)
# 3) Reads back the settings (getPushEventSettings)
# 4) Sends a test event from GravityZone (sendTestPushEvent)
#
# Run:
#   $env:GZ_API_KEY       = "gravityzone-api-key"
#   $env:SPLUNK_HEC_TOKEN = "splunk-hec-token"
#   powershell -ExecutionPolicy Bypass -File integrations\bitdefender\xdr_push_setup.ps1
# Optional:
#   $env:SPLUNK_HEC_URL = "https://13.53.133.248:8088/services/collector"   (default)
#   $env:GZ_API_URL     = "https://cloudgz.gravityzone.bitdefender.com/api"  (default)
#   -TestOnly : only read settings + send a test event (push already configured)

param([switch]$TestOnly)

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

$GzKey   = $env:GZ_API_KEY
$HecTok  = $env:SPLUNK_HEC_TOKEN
$HecUrl  = if ($env:SPLUNK_HEC_URL) { $env:SPLUNK_HEC_URL } else { "https://13.53.133.248:8088/services/collector" }
$GzApi   = if ($env:GZ_API_URL) { $env:GZ_API_URL.TrimEnd('/') } else { "https://cloudgz.gravityzone.bitdefender.com/api" }
if (-not $GzKey -or -not $HecTok) {
    Write-Host "[-] Evvelce yaz: `$env:GZ_API_KEY ve `$env:SPLUNK_HEC_TOKEN" -ForegroundColor Red; exit 1
}

function Get-ErrDetail($e) {
    if ($e.ErrorDetails -and $e.ErrorDetails.Message) { return $e.ErrorDetails.Message }
    if ($e.Exception.Response) {
        try { return (New-Object System.IO.StreamReader($e.Exception.Response.GetResponseStream())).ReadToEnd() } catch { }
    }
    return $e.Exception.Message
}

if (-not $TestOnly) {
# ---------------------------------------------------------------- 1) HEC test
Write-Host "`n>>> 1) Splunk HEC yoxlanilir ($HecUrl)..." -ForegroundColor Cyan
try {
    $ev = @{ index = "xdr"; sourcetype = "bitdefender:gravityzone"; source = "hec-test";
             event = @{ module = "hec-test"; message = "Splunk HEC isleyir (xdr_push_setup.ps1)" } } | ConvertTo-Json -Depth 5
    $r = Invoke-RestMethod -Uri $HecUrl -Method Post -Headers @{ Authorization = "Splunk $HecTok" } -Body $ev -ContentType "application/json"
    Write-Host "[+] HEC OK: $($r.text)" -ForegroundColor Green
} catch {
    Write-Host "[-] HEC islemedi (token / port 8088 / index xdr?):" -ForegroundColor Red
    Write-Host "    SEBEB: $(Get-ErrDetail $_)" -ForegroundColor DarkGray
    exit 1
}

}

# ---------------------------------------------------------------- GravityZone JSON-RPC
$GzAuth = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($GzKey):"))
function Invoke-Gz($method, $params) {
    $body = @{ jsonrpc = "2.0"; method = $method; params = $params; id = [guid]::NewGuid().ToString() } | ConvertTo-Json -Depth 10
    $r = Invoke-RestMethod -Uri "$GzApi/v1.0/jsonrpc/push" -Method Post -Headers @{ Authorization = $GzAuth } -Body $body -ContentType "application/json"
    if ($r.error) { throw ("GravityZone: " + ($r.error | ConvertTo-Json -Depth 6 -Compress)) }
    return $r.result
}

if (-not $TestOnly) {
# ---------------------------------------------------------------- 2) setPushEventSettings
Write-Host "`n>>> 2) GravityZone Event Push -> Splunk qurulur..." -ForegroundColor Cyan
$types = [ordered]@{
    "av" = $true; "avc" = $true; "aph" = $true; "fw" = $true; "hd" = $true; "dp" = $true; "uc" = $true
    "antiexploit" = $true; "ransomware-mitigation" = $true; "network-monitor" = $true; "new-incident" = $true
    "modules" = $true; "install" = $true; "uninstall" = $true; "registration" = $true; "task-status" = $true
    "endpoint-moved-in" = $true; "endpoint-moved-out" = $true; "hwid-change" = $true; "troubleshooting-activity" = $true
}
$settings = @{
    status = 1
    serviceType = "splunk"
    serviceSettings = @{
        url = $HecUrl
        authorization = "Splunk $HecTok"
        splunkAuthorization = "Splunk $HecTok"
        requireValidSslCertificate = $false
    }
    subscribeToEventTypes = $types
}
try {
    $res = Invoke-Gz "setPushEventSettings" $settings
    Write-Host "[+] setPushEventSettings OK: $res" -ForegroundColor Green
} catch {
    Write-Host "[-] setPushEventSettings alinmadi:" -ForegroundColor Red
    Write-Host "    SEBEB: $(if ($_.Exception.Message -like 'GravityZone:*') { $_.Exception.Message } else { Get-ErrDetail $_ })" -ForegroundColor DarkGray
    exit 1
}

Write-Host "[i] GravityZone API limiti ucun 30 saniye gozlenilir..." -ForegroundColor DarkGray
Start-Sleep -Seconds 30
}

# ---------------------------------------------------------------- 3) getPushEventSettings
try {
    $cur = Invoke-Gz "getPushEventSettings" @{}
    Write-Host "[i] Hazirki ayarlar: status=$($cur.status), serviceType=$($cur.serviceType), url=$($cur.serviceSettings.url)" -ForegroundColor Cyan
} catch { Write-Host "[!] getPushEventSettings oxunmadi: $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host "[i] GravityZone API limiti ucun 30 saniye gozlenilir..." -ForegroundColor DarkGray
Start-Sleep -Seconds 30

# ---------------------------------------------------------------- 4) sendTestPushEvent
Write-Host "`n>>> 3) GravityZone test hadisesi gonderilir..." -ForegroundColor Cyan
try {
    $res = Invoke-Gz "sendTestPushEvent" @{ eventType = "av"; data = @{ malware_name = "EICAR-Test-File (GravityZone push test)"; computer_name = "TEST-PC"; final_status = "deleted" } }
    Write-Host "[+] sendTestPushEvent OK. 1-2 deqiqe sonra Splunk-da yoxla: index=xdr" -ForegroundColor Green
} catch {
    Write-Host "[-] sendTestPushEvent alinmadi: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""
