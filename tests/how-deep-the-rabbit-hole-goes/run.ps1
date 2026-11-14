#Requires -Version 7.0
# Регресійний тест сканера how-deep-the-rabbit-hole-goes.
#   evil-skill    — класичний шкідливий скіл: мають знайтися всі очікувані загрози;
#   evil-plugin   — шкідливий плагін: хуки, MCP, маркетплейс, typosquatting, T21–T26;
#   evasion-skill — прийоми обходу: гомогліфи, base64, перенос рядка, псевдозаперечення, поліглот;
#   benign-skill  — легітимні патерни: нічого вище LOW;
#   clean-skill   — жодної знахідки.
$ErrorActionPreference = 'Stop'
$scan = Join-Path $PSScriptRoot '../../skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1'
$script:failed = 0

function Invoke-Scan([string]$name) {
    $out = pwsh -NoProfile -File $scan -Path (Join-Path $PSScriptRoot $name) -Json
    $code = $LASTEXITCODE
    try { $r = $out | ConvertFrom-Json } catch { $r = $null }
    if (-not $r) { Write-Host "✗ ${name}: сканер не повернув JSON (код $code)" -ForegroundColor Red; $script:failed++; return $null }
    $r | Add-Member ExitCode $code -PassThru
}
function Assert([bool]$ok, [string]$msg) {
    if ($ok) { Write-Host "✓ $msg" -ForegroundColor Green } else { Write-Host "✗ $msg" -ForegroundColor Red; $script:failed++ }
}
function Has($r, [string]$threat, [string]$sev, [string]$noteLike = '*', [string]$fileLike = '*') {
    [bool]($r.Findings | Where-Object { $_.Threat -eq $threat -and $_.Severity -eq $sev -and $_.Note -like $noteLike -and $_.File -like $fileLike })
}

# ---------- evil-skill ----------
if ($evil = Invoke-Scan 'evil-skill') {
    $expected = 'T01', 'T02', 'T03', 'T04', 'T05', 'T06', 'T07', 'T08', 'T09', 'T10', 'T11', 'T12', 'T16', 'T20'
    $missing = $expected | Where-Object { $_ -notin $evil.Findings.Threat }
    Assert (-not $missing) "evil-skill: знайдено всі $($expected.Count) очікуваних загроз$(if ($missing) { " — бракує $($missing -join ', ')" })"
    foreach ($note in 'поза папкою скіла', 'дані, а не інструкції', 'не відповідає вмісту', 'розкодування') {
        Assert ([bool]($evil.Findings | Where-Object { $_.Note -like "*$note*" })) "evil-skill: є знахідка «$note»"
    }
    Assert (Has $evil 'T06' 'HIGH') 'evil-skill: «НЕ» у заголовку H1 не знижує рівень секретів'
    Assert (Has $evil 'T07' 'CRITICAL' '*комбінація*') 'evil-skill: секрети + канал назовні = CRITICAL'
    Assert (Has $evil 'T05' 'CRITICAL' '*розкодованому base64*') 'evil-skill: -EncodedCommand розкодовано й перевірено'
    Assert ($evil.ExitCode -eq 2) 'evil-skill: код виходу 2'
    Assert ($evil.TreeHash -match '^[0-9a-f]{64}$' -and $evil.Inventory.Count -eq 2) 'evil-skill: є хеш дерева та інвентар'
}

# ---------- evil-plugin ----------
if ($plugin = Invoke-Scan 'evil-plugin') {
    $expected = 'T11', 'T12', 'T13', 'T21', 'T22', 'T23', 'T24', 'T25', 'T26'
    $missing = $expected | Where-Object { $_ -notin $plugin.Findings.Threat }
    Assert (-not $missing) "evil-plugin: знайдено всі $($expected.Count) очікуваних загроз$(if ($missing) { " — бракує $($missing -join ', ')" })"
    Assert (Has $plugin 'T21' 'HIGH' '*хуки плагіна*' 'hooks/hooks.json') 'evil-plugin: hooks.json позначено як автозапуск'
    Assert (Has $plugin 'T05' 'CRITICAL' '*' 'hooks/hooks.json') 'evil-plugin: команду хука перевірено правилами'
    Assert (Has $plugin 'T21' 'HIGH' '*MCP-сервери*' '.mcp.json') 'evil-plugin: .mcp.json позначено'
    Assert (Has $plugin 'T21' 'HIGH' '*динамічна команда*') 'evil-plugin: динамічна команда !`…` у SKILL.md'
    Assert (Has $plugin 'T11' 'MEDIUM' '*без зафіксованого sha*') 'evil-plugin: зовнішнє джерело в marketplace.json'
    Assert (Has $plugin 'T12' 'HIGH' '*typosquatting*') 'evil-plugin: назва-двійник вбудованого скіла'
    Assert (Has $plugin 'T24' 'CRITICAL' '*API-трафіку*') 'evil-plugin: підміна ANTHROPIC_BASE_URL'
    Assert (Has $plugin 'T05' 'CRITICAL' '*reverse shell*') 'evil-plugin: зворотна оболонка'
}

# ---------- evasion-skill ----------
if ($evasion = Invoke-Scan 'evasion-skill') {
    Assert (Has $evasion 'T01' 'CRITICAL' '*нормалізації*') 'evasion-skill: гомогліф у «ignore previous instructions»'
    Assert (Has $evasion 'T05' 'CRITICAL' '*розкодованому base64*') 'evasion-skill: curl | bash усередині base64'
    Assert (Has $evasion 'T05' 'CRITICAL' '*' 'scripts/setup.sh') 'evasion-skill: curl | sh, розбитий переносом рядка'
    Assert ((Has $evasion 'T06' 'HIGH') -and -not ($evasion.Findings | Where-Object { $_.Threat -eq 'T06' -and $_.Note -like '*заборони*' })) 'evasion-skill: «do not forget» не вважається забороною'
    Assert (Has $evasion 'T03' 'MEDIUM' 'without confirmation') 'evasion-skill: «without confirmation» не знижує сам себе'
    Assert (Has $evasion 'T02' 'CRITICAL' '*невидимі*') 'evasion-skill: variation selectors (U+E0100…)'
    Assert (Has $evasion 'T02' 'MEDIUM' '*текст посилання*') 'evasion-skill: посилання показує один домен, а веде на інший'
    Assert (Has $evasion 'T19' 'MEDIUM' '*після кінця зображення*') 'evasion-skill: дані після кінця PNG'
    Assert (Has $evasion 'T02' 'HIGH' '*усередині зображення*') 'evasion-skill: текст-інструкція всередині зображення'
    Assert (Has $evasion 'T19' 'HIGH' '*подвійне розширення*') 'evasion-skill: подвійне розширення'
}

# ---------- benign-skill: легітимні патерни (заборони, PNG, shebang, SVG-коментарі, base64 з API) ----------
if ($benign = Invoke-Scan 'benign-skill') {
    $noisy = @($benign.Findings | Where-Object Severity -ne 'LOW')
    $noisy | ForEach-Object { Write-Host "  $($_.Severity) $($_.Threat) $($_.File):$($_.Line) $($_.Note)" -ForegroundColor Red }
    Assert (-not $noisy -and $benign.ExitCode -eq 0) "benign-skill: нічого вище LOW (LOW: $(@($benign.Findings).Count))"
}

# ---------- clean-skill ----------
if ($clean = Invoke-Scan 'clean-skill') {
    Assert (-not $clean.Findings.Count) "clean-skill: без знахідок$(if ($clean.Findings.Count) { " — хибні тривоги: $($clean.Findings.Threat -join ', ')" })"
}

Write-Host ''
if ($script:failed) { Write-Host "Провалено перевірок: $script:failed" -ForegroundColor Red } else { Write-Host 'Усі перевірки пройдено.' -ForegroundColor Green }
exit $script:failed
