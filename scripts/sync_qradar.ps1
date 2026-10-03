# SOC-Detection-Rules -> QRadar (REST API) | PowerShell 5.1 compatible
#
# Pipeline (GitHub -> API -> QRadar):
#   1. Reads rules\qradar\*.yml
#   2. Validates every AQL filter on QRadar via /api/ariel/searches
#   3. Builds a QRadar content bundle (custom_rule XML, same format as contentManagement.pl export) -> zip
#   4. Uploads the zip via /api/config/extension_management/extensions
#   5. Removes old QR-* rules not created by this pipeline, installs the bundle (INSTALL, overwrite)
#   6. Verifies QR-* rules in /api/analytics/rules
#
# Run (inside repo folder):
#   $env:QRADAR_HOST  = "https://QRADAR_IP"
#   $env:QRADAR_TOKEN = "authorized-service-token"
#   powershell -ExecutionPolicy Bypass -File scripts\sync_qradar.ps1              # validate + deploy
#   powershell -ExecutionPolicy Bypass -File scripts\sync_qradar.ps1 -ValidateOnly # only AQL check

param([switch]$ValidateOnly)

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

$Base  = $env:QRADAR_HOST
$Token = $env:QRADAR_TOKEN
if (-not $Base -or -not $Token) {
    Write-Host "[-] Evvelce yaz: `$env:QRADAR_HOST='https://IP' ve `$env:QRADAR_TOKEN='token'" -ForegroundColor Red
    exit 1
}
$Base = $Base.TrimEnd('/')
$Headers = @{ "SEC" = $Token; "Accept" = "application/json" }

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
    $m = [regex]::Match($txt, '"message"\s*:\s*"(.*?)"')
    if ($m.Success) { return $m.Groups[1].Value }
    $m = [regex]::Match($txt, '"description"\s*:\s*"(.*?)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return $txt
}

function Get-Field($c, $key) {
    return [regex]::Match($c, '(?m)^' + $key + ':\s*"?([^"\r\n]*?)"?\s*$').Groups[1].Value
}

function Esc-Xml($s) {
    return [System.Security.SecurityElement]::Escape($s)
}

function Get-StableGuid($text) {
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $b = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return ([guid]::new($b)).ToString()
}

Write-Host "`n>>> QRadar-a qosulurum ($Base)...`n" -ForegroundColor Cyan

try {
    $about = Invoke-RestMethod -Uri "$Base/api/system/about" -Method Get -Headers $Headers
    Write-Host "[i] QRadar baglantisi OK. Versiya: $($about.external_version)" -ForegroundColor Cyan
} catch {
    Write-Host "[-] QRadar-a qosulmaq alinmadi:" -ForegroundColor Red
    Write-Host "    SEBEB: $(Get-ErrDetail $_)" -ForegroundColor DarkGray
    exit 1
}

# ---------------------------------------------------------------------------
# 1) YAML-lari oxu + 2) AQL filter-leri QRadar-da yoxla
# ---------------------------------------------------------------------------
$rules = @(); $bad = 0
Get-ChildItem "rules\qradar" -Filter "q_rule_*.yml" | Sort-Object Name | ForEach-Object {
    $c = Get-Content $_.FullName -Raw -Encoding UTF8
    $r = [ordered]@{
        Id       = Get-Field $c 'id'
        Name     = Get-Field $c 'name'
        DescAz   = Get-Field $c 'description_az'
        Mitre    = Get-Field $c 'mitre'
        Type     = (Get-Field $c 'rule_type').ToUpper()
        Filter   = Get-Field $c 'rule_filter'
        Count    = [int](Get-Field $c 'threshold_count')
        Fields   = Get-Field $c 'threshold_fields'
        Minutes  = [int](Get-Field $c 'threshold_minutes')
        Severity = [int](Get-Field $c 'qradar_severity')
    }
    if (-not $r.Id -or -not $r.Filter -or $r.Type -notin @("EVENT","FLOW")) {
        Write-Host "[-] Skip (id/rule_filter/rule_type oxunmadi): $($_.Name)" -ForegroundColor Red
        $bad++; return
    }
    $full = "$($r.Id) - $($r.Name)"
    $table = if ($r.Type -eq "FLOW") { "flows" } else { "events" }
    try {
        $aql = "SELECT COUNT(*) AS cnt FROM $table WHERE $($r.Filter) LAST 5 MINUTES"
        $s = Invoke-RestMethod -Uri "$Base/api/ariel/searches?query_expression=$([uri]::EscapeDataString($aql))" -Method Post -Headers $Headers
        Write-Host "[+] AQL OK: $full" -ForegroundColor Green
        $script:rules += [pscustomobject]$r
    } catch {
        Write-Host "[-] AQL XETA: $full" -ForegroundColor Red
        Write-Host "    SEBEB: $(Get-ErrDetail $_)" -ForegroundColor DarkGray
        $script:bad++
    }
}

if ($bad -gt 0) { Write-Host "`n[-] $bad qaydada xeta var. Deploy dayandirildi.`n" -ForegroundColor Red; exit 1 }
if ($ValidateOnly) { Write-Host "`n>>> Yoxlama bitdi: $($rules.Count) qayda duzgundur.`n" -ForegroundColor Cyan; exit 0 }

# ---------------------------------------------------------------------------
# 3) Content bundle (XML) qur
# ---------------------------------------------------------------------------
$now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$ourUuids = @{}
$sb = New-Object System.Text.StringBuilder
[void]$sb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + "`n<content>`n")
[void]$sb.Append("    <qradarversion>2021.6.14.20251017194912</qradarversion>`n")

$n = 0
foreach ($r in $rules) {
    $n++
    $rid   = 990000 + $n
    $uuid  = Get-StableGuid "soc-detection-rules/$($r.Id)"
    $ourUuids[$uuid] = $true
    $word  = if ($r.Type -eq "FLOW") { "flow" } else { "event" }
    $words = "$($word)s"
    $full  = "$($r.Id) - $($r.Name)"
    $notes = "$($r.DescAz) MITRE: $($r.Mitre). Source: github.com/blue-team021/SOC-Detection-Rules"

    # Test 1: AQL filter (com.q1labs.semsources.cre.tests.AQL_Test)
    $q    = $r.Filter
    $enc  = [uri]::EscapeDataString($q) + "|" + [uri]::EscapeDataString('["' + $q.Replace('"','\"') + '"]')
    $t1 = "<test id=`"318`" name=`"com.q1labs.semsources.cre.tests.AQL_Test`" uid=`"0`" group=`"jsp.qradar.rulewizard.condition.page.group.common`" groupId=`"1`" requiredCapabilities=`"EventViewer.RULECREATION|SURVEILLANCE.RULECREATION`">" +
          "<text>when the $word matches &lt;a href='javascript:editParameter(`"0`", `"1`")' class='dynamic'&gt;$(Esc-Xml $q)&lt;/a&gt; AQL filter query</text>" +
          "<parameter id=`"1`"><initialText>this</initialText><selectionLabel>Enter an AQL filter query</selectionLabel><userOptions format=`"CustomizeParameter-AQL.jsp`" source=`"user`"/>" +
          "<userSelection>$(Esc-Xml $enc)</userSelection><userSelectionTypes>property</userSelectionTypes><userSelectionId>0</userSelectionId></parameter>" +
          "<parameter id=`"2`"><initialText></initialText><selectionLabel>Select a value</selectionLabel><userSelection>$words</userSelection><userSelectionId>0</userSelectionId></parameter></test>"

    # Test 2 (optional): threshold (com.q1labs.semsources.cre.tests.functions.MatchCount)
    $t2 = ""
    if ($r.Count -gt 0) {
        $W = if ($r.Type -eq "FLOW") { "Flow" } else { "Event" }
        $labels = ($r.Fields -split '\s*,\s*' | ForEach-Object {
            switch ($_) { "sourceIP" {"Source IP"} "destinationIP" {"Destination IP"} "userName" {"Username"} "destinationPort" {"Destination Port"} default {$_} }
        }) -join ", "
        $t2 = "<test id=`"300`" name=`"com.q1labs.semsources.cre.tests.functions.MatchCount`" uid=`"1`" group=`"jsp.qradar.rulewizard.condition.page.group.functions.counters`" groupId=`"4`" requiredCapabilities=`"EventViewer.RULECREATION|SURVEILLANCE.RULECREATION`">" +
              "<text>when at least &lt;a href='javascript:editParameter(`"1`", `"2`")' class='dynamic'&gt;$($r.Count)&lt;/a&gt; $words are seen with the same &lt;a href='javascript:editParameter(`"1`", `"3`")' class='dynamic'&gt;$labels&lt;/a&gt; in &lt;a href='javascript:editParameter(`"1`", `"5`")' class='dynamic'&gt;$($r.Minutes)&lt;/a&gt; &lt;a href='javascript:editParameter(`"1`", `"6`")' class='dynamic'&gt;minutes&lt;/a&gt;</text>" +
              "<parameter id=`"1`"><name>get$($W)Rules</name><initialText>these rules</initialText><selectionLabel>Select the rule(s)</selectionLabel><userOptions format=`"list`" source=`"class`" method=`"com.q1labs.sem.ui.semservices.UISemServices.get$($W)Rules`" multiselect=`"true`"/><userSelection> </userSelection><userSelectionId>0</userSelectionId></parameter>" +
              "<parameter id=`"2`"><initialText>this many</initialText><selectionLabel>Enter a value</selectionLabel><userOptions format=`"user`" validation=`"com.q1labs.core.ui.util.ValidatorUtils.validatePositiveNumber`" errorkey=`"30001`" multiselect=`"false`"/><userSelection>$($r.Count)</userSelection><userSelectionTypes></userSelectionTypes><userSelectionId>0</userSelectionId></parameter>" +
              "<parameter id=`"3`"><initialText>$word properties</initialText><selectionLabel>Select a $word property and click 'Add'</selectionLabel><userOptions format=`"list`" source=`"class`" method=`"com.q1labs.sem.ui.semservices.UISemServices.get$($W)DatabaseFields`" multiselect=`"true`"/><userSelection>$($r.Fields)</userSelection><userSelectionTypes></userSelectionTypes><userSelectionId>0</userSelectionId></parameter>" +
              "<parameter id=`"4`"><initialText>$word properties</initialText><selectionLabel>Select a $word property and click 'Add'</selectionLabel><userOptions format=`"list`" source=`"class`" method=`"com.q1labs.sem.ui.semservices.UISemServices.get$($W)DatabaseFields`" multiselect=`"true`"/><userSelection> </userSelection><userSelectionId>0</userSelectionId></parameter>" +
              "<parameter id=`"5`"><initialText>this many</initialText><selectionLabel>Enter a value</selectionLabel><userOptions format=`"user`" validation=`"com.q1labs.core.ui.util.ValidatorUtils.validatePositiveNumber`" errorkey=`"30001`" multiselect=`"false`"/><userSelection>$($r.Minutes)</userSelection><userSelectionTypes></userSelectionTypes><userSelectionId>0</userSelectionId></parameter>" +
              "<parameter id=`"6`"><initialText>minutes</initialText><selectionLabel>Select a time unit</selectionLabel><userOptions format=`"list`" source=`"xml`" multiselect=`"false`"><option id=`"m`">minutes</option><option id=`"h`">hour(s)</option><option id=`"d`">day(s)</option></userOptions><userSelection>m</userSelection><userSelectionId>0</userSelectionId></parameter></test>"
    }

    $ruleXml = "<rule id=`"$rid`" enabled=`"true`" buildingBlock=`"false`" roleDefinition=`"false`" type=`"$($r.Type)`" scope=`"LOCAL`" owner=`"admin`">" +
               "<name>$(Esc-Xml $full)</name><notes>$(Esc-Xml $notes)</notes>" +
               "<testDefinitions>$t1$t2</testDefinitions>" +
               "<actions offenseMapping=`"0`" forceOffenseCreation=`"true`" includeAttackerEventsInterval=`"0`" flowAnalysisInterval=`"0`"><alterMetric metric=`"setSeverity`" operation=`"setSeverity`" value=`"$($r.Severity)`"/></actions></rule>"
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($ruleXml))
    $rtype = if ($r.Type -eq "FLOW") { "4" } else { "0" }

    [void]$sb.Append("    <custom_rule>`n")
    [void]$sb.Append("        <base_capacity>0</base_capacity>`n        <origin>USER</origin>`n        <flags>0</flags>`n")
    [void]$sb.Append("        <mod_date>$now</mod_date>`n        <rule_data>$b64</rule_data>`n        <uuid>$uuid</uuid>`n")
    [void]$sb.Append("        <capacity_timestamp>0</capacity_timestamp>`n        <rule_type>$rtype</rule_type>`n        <average_capacity>0</average_capacity>`n")
    [void]$sb.Append("        <base_host_id>53</base_host_id>`n        <id>$rid</id>`n        <create_date>$now</create_date>`n")
    [void]$sb.Append("    </custom_rule>`n")
}
[void]$sb.Append("</content>`n")

$buildDir = Join-Path (Get-Location) "build"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
$xmlPath = Join-Path $buildDir "soc_detection_rules_qradar.xml"
$zipPath = Join-Path $buildDir "soc_detection_rules_qradar.zip"
[System.IO.File]::WriteAllText($xmlPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $xmlPath -DestinationPath $zipPath
Write-Host "`n[i] Content bundle hazirdir: build\soc_detection_rules_qradar.zip ($($rules.Count) qayda)" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 4) Zip-i API ile QRadar-a yukle (multipart/form-data, curl.exe ile)
# ---------------------------------------------------------------------------
$upOut = & curl.exe -s -k -X POST -H "SEC: $Token" -H "Accept: application/json" -F "file=@$zipPath" "$Base/api/config/extension_management/extensions"
try { $ext = $upOut | ConvertFrom-Json } catch { $ext = $null }
if (-not $ext -or -not $ext.id) {
    Write-Host "[-] Yukleme alinmadi. QRadar cavabi:" -ForegroundColor Red
    Write-Host "    $upOut" -ForegroundColor DarkGray
    exit 1
}
Write-Host "[+] Extension yuklendi. ID: $($ext.id), status: $($ext.status)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 5) Kohne (el ile yaradilmis) QR-* qaydalarini sil, sonra INSTALL
# ---------------------------------------------------------------------------
try {
    $flt = [uri]::EscapeDataString('name ILIKE "QR-%"')
    $raw = Invoke-RestMethod -Uri "$Base/api/analytics/rules?filter=$flt" -Method Get -Headers $Headers
    $existing = @($raw | ForEach-Object { $_ })
    foreach ($e in $existing) {
        if ($e.identifier -and $ourUuids.ContainsKey($e.identifier)) { continue }
        try {
            Invoke-RestMethod -Uri "$Base/api/analytics/rules/$($e.id)" -Method Delete -Headers $Headers | Out-Null
            Write-Host "[x] Kohne qayda silindi: $($e.name)" -ForegroundColor DarkYellow
        } catch { Write-Host "[-] Silinmedi: $($e.name) -> $(Get-ErrDetail $_)" -ForegroundColor Red }
    }
    if ($existing.Count -gt 0) { Start-Sleep -Seconds 10 }
} catch { Write-Host "[!] Movcud qaydalar oxunmadi: $(Get-ErrDetail $_)" -ForegroundColor Yellow }

try {
    $task = Invoke-RestMethod -Uri "$Base/api/config/extension_management/extensions/$($ext.id)?action_type=INSTALL&overwrite=true" -Method Post -Headers $Headers
} catch {
    Write-Host "[-] INSTALL alinmadi:" -ForegroundColor Red
    Write-Host "    SEBEB: $(Get-ErrDetail $_)" -ForegroundColor DarkGray
    exit 1
}
$sid = if ($task.status_id) { $task.status_id } else { $task.id }
Write-Host "[i] Qurasdirma basladi (task $sid)..." -ForegroundColor Cyan
$st = $null
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 3
    try { $st = Invoke-RestMethod -Uri "$Base/api/config/extension_management/extensions_task_status/$sid" -Method Get -Headers $Headers } catch { continue }
    if ($st.status -in @("COMPLETED","ERROR","EXCEPTION","CANCELLED","CONFLICT")) { break }
}
if ($st.status -ne "COMPLETED") {
    Write-Host "[-] Qurasdirma neticesi: $($st.status)" -ForegroundColor Red
    Write-Host "    $($st | ConvertTo-Json -Depth 6 -Compress)" -ForegroundColor DarkGray
    exit 1
}
Write-Host "[+] Qurasdirma bitdi: COMPLETED" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6) Yoxlama
# ---------------------------------------------------------------------------
Start-Sleep -Seconds 3
$flt = [uri]::EscapeDataString('name ILIKE "QR-%"')
$raw = Invoke-RestMethod -Uri "$Base/api/analytics/rules?filter=$flt&fields=id,name,enabled,type,origin" -Method Get -Headers $Headers
$final = @($raw | ForEach-Object { $_ }) | Sort-Object name
foreach ($x in $final) { Write-Host ("[QRadar] {0,-62} type={1,-6} enabled={2}" -f $x.name, $x.type, $x.enabled) -ForegroundColor Green }
Write-Host "`n>>> Netice: QRadar-da $(@($final).Count) QR-* qaydasi var (GitHub-da $($rules.Count)).`n" -ForegroundColor Cyan
