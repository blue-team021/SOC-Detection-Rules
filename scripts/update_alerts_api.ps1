[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$adminEmail = "finalp844@gmail.com"

$server = "13.53.133.248"
$port = "8089"
$user = "millisec"
$pass = "Salam necesen@123"

Write-Host "[*] Splunk-a qoşulur..." -ForegroundColor Cyan
$loginUri = "https://" + $server + ":" + $port + "/services/auth/login"
$loginResponse = Invoke-RestMethod -Uri $loginUri -Method Post -Body @{ username = $user; password = $pass }
$sessionKey = $loginResponse.response.sessionKey
$headers = @{ Authorization = "Splunk $sessionKey" }

Write-Host "[*] Splunk-dan real qayda adlari cekilir..." -ForegroundColor Cyan
$searchUri = "https://" + $server + ":" + $port + "/servicesNS/nobody/search/saved/searches?output_mode=json&count=0"
$searches = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $headers

foreach ($entry in $searches.entry) {
    $exactName = $entry.name
    # Yalnız "SPL-" ilə başlayan qaydaları seçirik
    if ($exactName -match "^SPL-") {
        $encodedName = [uri]::EscapeDataString($exactName)
        $updateUri = "https://" + $server + ":" + $port + "/servicesNS/nobody/search/saved/searches/$encodedName"

        $body = @{
            "action.email" = "1"
            "action.email.to" = $adminEmail
            "action.email.subject" = "🚨 SOC İnsidenti (OWASP): $exactName"
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
            Write-Host "[+] Qayda yeniləndi və E-mail Alert qoşuldu: $exactName" -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Xəta ($exactName): $_" -ForegroundColor Yellow
        }
    }
}
Write-Host "[*] Bütün qaydalara Email Alert sistemi tam inteqrasiya olundu!" -ForegroundColor Cyan