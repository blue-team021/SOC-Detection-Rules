[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$adminEmail = "finalp844@gmail.com"

$server = "13.53.133.248"
$port = "8089"
$user = "millisec"
$pass = "Salam necesen@123"

Write-Host "[*] Splunk-a qoşulur..." -ForegroundColor Cyan
$loginUri = "https://" + $server + ":" + $port + "/services/auth/login"
$loginBody = @{ username = $user; password = $pass }
$loginResponse = Invoke-RestMethod -Uri $loginUri -Method Post -Body $loginBody
$sessionKey = $loginResponse.response.sessionKey

$rulesPath = "rules\splunk"
$headers = @{ Authorization = "Splunk $sessionKey" }

Get-ChildItem -Path $rulesPath -Filter "*.yml" | ForEach-Object {
    $file = $_
    $content = Get-Content -Path $file.FullName -Raw
    if ($content -match 'id:\s*"?([^\\r\\n"]+)"?') { $ruleId = $Matches[1] } else { $ruleId = $file.BaseName }
    if ($content -match 'name:\s*"?([^\\r\\n"]+)"?') { $ruleName = $Matches[1] } else { $ruleName = $ruleId }
    
    # Qaydanın tam adı url-encode olunmalıdır ki, API yeniləmə (Update) edə bilsin
    $fullRuleName = "$ruleId - $ruleName"
    $encodedName = [uri]::EscapeDataString($fullRuleName)
    $updateUri = "https://" + $server + ":" + $port + "/servicesNS/nobody/search/saved/searches/$encodedName"

    # Yalnız Alert və Email parametrlərini əlavə edirik
    $body = @{
        "action.email" = "1"
        "action.email.to" = $adminEmail
        "action.email.subject" = "🚨 SOC İnsidenti (OWASP): $ruleId"
        "action.email.message.alert" = "Sistemdə təhlükəsizlik qaydası pozuldu və hücum detect edildi! Təcili Splunk panelini yoxlayın."
        "action.email.sendresults" = "1"
        "action.email.inline" = "1"
        "alert_type" = "number of events"
        "alert_comparator" = "greater than"
        "alert_threshold" = "0"
        "is_scheduled" = "1"
    }

    try {
        Invoke-RestMethod -Uri $updateUri -Method Post -Headers $headers -Body $body | Out-Null
        Write-Host "[+] Qayda yeniləndi və E-mail Alert qoşuldu: $ruleId" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Xəta ($ruleId): $_" -ForegroundColor Yellow
    }
}
Write-Host "[*] Bütün qaydalara Email Alert sistemi tam inteqrasiya olundu!" -ForegroundColor Cyan