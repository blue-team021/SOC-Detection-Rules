# QRadar qaydalari: GitHub -> API -> QRadar

Qaydalar QRadar UI-da el ile YARADILMIR. Butun ish `scripts/sync_qradar.ps1` ile API uzerinden gedir.

## Axin
1. Qayda GitHub-da YAML kimi yazilir: `rules/qradar/q_rule_XX_*.yml`
   - `rule_type`: EVENT ve ya FLOW
   - `rule_filter`: QRadar AQL filter (qaydanin esas sherti)
   - `threshold_count` / `threshold_fields` / `threshold_minutes`: hedd (0 = hedd yoxdur)
   - `qradar_severity`: offense ciddiliyi (1-10)
   - `aql_query`: tehlil (threat hunting) ucun tam AQL sorgusu
2. `sync_qradar.ps1`:
   - her `rule_filter`-i `/api/ariel/searches` ile QRadar-da yoxlayir (sintaksis)
   - QRadar content bundle (custom_rule XML, contentManagement.pl export formati) ve zip qurur
   - zip-i `/api/config/extension_management/extensions` ile QRadar-a yukleyir
   - kohne/el ile yaradilmis `QR-*` qaydalarini `/api/analytics/rules/{id}` ile silir
   - bundle-i `action_type=INSTALL&overwrite=true` ile qurasdirir
   - `/api/analytics/rules` ile neticeni yoxlayir
3. Her qaydanin sabit UUID-si var (id-den yaranir), ona gore tekrar isledende qayda yenilenir, dublikat yaranmir.

## Islemek
```
$env:QRADAR_HOST  = "https://QRADAR_IP"
$env:QRADAR_TOKEN = "authorized-service-token"
powershell -ExecutionPolicy Bypass -File scripts\sync_qradar.ps1              # yoxla + deploy
powershell -ExecutionPolicy Bypass -File scripts\sync_qradar.ps1 -ValidateOnly # yalniz AQL yoxlamasi
```

## Qeydler
- QR-003 ve QR-004 flow (sebeke axini) melumati teleb edir.
- QR-007 Sysmon teleb edir.
- XML formati QRadar 7.5.0 UP14-den ixrac olunmus qaydaya esasen qurulub (contentManagement.pl -a export -c customrule).
