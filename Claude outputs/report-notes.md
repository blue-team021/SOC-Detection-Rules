# Hesabat ucun qeydler (Pervin: bend 7, 9, 12, 13, 20, 24, 29, 32)

Qayda: hesabata YALNIZ ugurlu/isleyen netice sekilleri girir. Xeta ekranlari girmir.

## Hesabata girecek sekiller (toplanilanlar)
- [ ] Splunk-da index/sourcetype siyahisi (main, tpot, vuln; WinEventLog, bestrio:api:json)
- [x] Event 4720 (yeni istifadeci) Splunk-da tapildi + rex ile created_by
- [x] Gmail SMTP quruldu, test mail gəldi (sendemail)
- [x] T1136 alerti (Edit Alert ekrani: cron */5, throttle, email action)
- [x] Terminal: `Netice: 17 ugurlu, 0 ugursuz` (sync_siem.ps1 ile GitHub -> Splunk)
- [x] Splunk Searches/Alerts siyahisi (SPL-001...SPL-017, Description sutunu)
- [x] Hucum simulyasiyasi: bestrio.shop/api/v1/products/1'%20UNION%20SELECT%201,2-- (brauzer)
- [x] Splunk-da hucum hadisesi (path=...UNION..., status 404, src_ip)
- [x] Gmail: "Splunk Alert: SPL-001 - OWASP - SQL Injection" maili (netice cedveli ile)
- [ ] Gmail: Azerbaycan dilinde duzgun herfli yeni mail
- [ ] GitHub repo: rules/splunk (17) + scripts/sync_siem.ps1 + commit tarixcesi
- [ ] QRadar qaydalari (10) + tetiklenmis offense
- [ ] Sysmon qurasdirilmasi + SPL-006/009/014 testi

## Qalan bendler
12/13 Bitdefender XDR + siyasetler; 29 Keycloak IAM/SSO/MFA; 24 DFIR/Volatility; 20 Cobalt Strike aşkarlama testi; 32 Krizis idareetmesi logu.

## Tehlukesizlik qeydi
Splunk parolu GitHub tarixcesinde ve yazismada gorunub -> deyisdirilmeli, repo private edilmeli.
