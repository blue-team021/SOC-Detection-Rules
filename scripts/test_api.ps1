[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$uri = "https://13.53.133.248:8089/services/auth/login"
$body = @{ username = "millisec"; password = "Salam necesen@123" }
try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body
    $sessionKey = $response.response.sessionKey
    Write-Host "[+] Başarıyla giriş yapıldı! SessionKey alındı." -ForegroundColor Green
    
    $createUri = "https://13.53.133.248:8089/servicesNS/nobody/search/saved/searches"
    $headers = @{ Authorization = "Splunk $sessionKey" }
    $ruleBody = @{ 
        name = "SPL-001 - Test Rule"
        search = "index=_internal | head 1"
        is_scheduled = "1"
        cron_schedule = "*/5 * * * *"
    }
    
    $res = Invoke-RestMethod -Uri $createUri -Method Post -Headers $headers -Body $ruleBody
    Write-Host "[+] Kural başarıyla Splunk'a eklendi!" -ForegroundColor Green
    $res
}
catch {
    Write-Host "[-] Hata oluştu: $_" -ForegroundColor Red
}
