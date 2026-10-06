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
- [x] QRadar: sync_qradar.ps1 -> `QRadar baglantisi OK. Versiya: 7.5.0`, 10 AQL OK (GitHub -> QRadar API)
- [x] QRadar: sync_qradar.ps1 deploy neticesi (10 AQL OK -> upload -> INSTALL COMPLETED -> 10 QR-* qaydasi)
- [x] QRadar Offenses -> Rules siyahisi (QR-001...QR-010, Event/Flow, Enabled=True, Origin=User)
- [ ] Tetiklenmis offense (test hucumu)
- Qeyd: QRadar qayda formati contentManagement.pl export-dan (QR-001 sablon) alindi; qaydalar UI-da el ile yaradilmir
- Qeyd: QRadar ucun mail bildirisi TELEB OLUNMUR (yalniz offense yetər)
- [ ] Sysmon qurasdirilmasi + SPL-006/009/014 testi

## Bend 12-13 (Bitdefender GravityZone XDR)
- [x] Splunk: index `xdr` + HEC token bitdefender-xdr (sourcetype bitdefender:gravityzone)
- Qeyd: Push (https) yolu HEC SSL teleb edirdi -> komandanin http inteqrasiyalarini pozdu -> geri qaytarildi. Yeni yol: PULL poller (gz_xdr_poller.py, Splunk serverde cron */5, HEC http localhost)
- [x] gz_xdr_poller.py Splunk servere qurasdirildi (/opt/gz_xdr, config /etc/gz_xdr.conf chmod 600); index=xdr source=gz_xdr_poller module=poller-heartbeat gorunur (errors=[], note: Incidents API lisenziyada yoxdur)
- [x] cron /etc/cron.d/gz_xdr (*/5) isleyir: 24 saatda 263 heartbeat, errors bos
- [x] GravityZone API key (Event Push Service, Network, Incidents, Policies), Access URL cloudgz
- [x] xdr_push_setup.ps1: HEC OK -> setPushEventSettings OK -> status=1 serviceType=splunk -> sendTestPushEvent OK
- [x] Splunk: index=xdr -> GravityZone test hadisesi (EICAR-Test-File, module=av, _testEvent_=true, source=Bitdefender-xdr)
- [x] Policy: MilliSec-BlueTeam-Workstations (maks qoruma, Risk Management, USB blok + SanDisk Device ID istisna, Bluetooth blok, Encryption, Patch Mgmt, Sandbox)
- [~] Policy: MilliSec-BlueTeam-Servers yaradildi (klon) - server ferqleri tetbiq olunmali
- [ ] (SONDA) Agentler: web server, mail server, Splunk server, DC01, DC02, 2 client -> Network sehifesi
- Qeyd: QRadar appliance-e agent qurulmur (IBM appliance) - hesabatda istisna kimi yaz

## Bend 29 (Keycloak IAM / SSO / MFA)
- [x] Sistem 1: Splunk SAML SSO + OTP (Hello, pervin)
- [x] Sistem 2: QRadar SAML SSO + OTP
  - Keycloak client: Client ID https://16.192.154.37/console, NameID=username, Sign documents+assertions On, Client signature required Off, ACS https://16.192.154.37/console/SAMLSSOAssertionConsumerService
  - Valid redirect URIs: https://16.192.154.37/console/*, https://qradar.localdomain/*, http://qradar.localdomain/*
  - QRadar Authentication Module = SAML 2.0 (metadata: /realms/MilliSec/protocol/saml/descriptor), NameID Unspecified, HTTP-POST, Signed=Yes, Encrypted=No, Authorize=Local
  - QRadar users: pervin, nuray, vusal, zumrud (Admin); admin = Local Only + Local Authentication Fallback (IdP cokerse ehtiyat giris)
  - QRadar oz hostname-ini (qradar.localdomain) ACS kimi gonderir -> her istifadecinin PC-sinde hosts: 16.192.154.37 qradar.localdomain; giris unvani https://qradar.localdomain/console
  - Ortaq "admin" veb girisi baglandi -> her kes oz adi + MFA (ferdi hesabatliliq, audit)
  - Keycloak Events (MilliSec) Save events On -> LOGIN / LOGIN_ERROR audit
- Screenshotlar: Keycloak QRadar client (Settings/SAML capabilities/Signature), QRadar SAML formu, Keycloak giris ekrani (QRadar-dan yonlenme), QRadar Dashboard (pervin), Users siyahisi (5 istifadeci, Fallback sutunu)
- [ ] Sistem 3 (Intranet/Service Desk) - Vusal/Nuray-dan URL lazim
- [ ] AD/LDAP inteqrasiyasi - DC VM-de (AWS-den catilmir), sonraya
- [ ] Keycloak: daimi admin yarat, temporary admin-i sil (sari banner)

## Qalan bendler
12/13 Bitdefender XDR + siyasetler; 29 Keycloak IAM/SSO/MFA; 24 DFIR/Volatility; 20 Cobalt Strike aşkarlama testi; 32 Krizis idareetmesi logu.

## Tehlukesizlik qeydi
Splunk parolu GitHub tarixcesinde ve yazismada gorunub -> deyisdirilmeli, repo private edilmeli.

## HESABAT QAYDASI (vacib)
- Umumi report 300 sehifeni KECMEMELIDIR (eks halda qebul olunmur).
- 4 nefer -> adam basina ~65-70 sehife.
- Pervin-in hissesi: bend 7, 9, 12, 13, 20, 24, 29, 32.
- Yazanda yigcam ol: her bend ucun qisa izah + addim + SUBUT screenshot. Artiq soz yox.
- Yalniz ugurlu/isleyen screenshotlar (xeta ekranlari yox).
- Parol/token gorunen yerler qaraldilir.
