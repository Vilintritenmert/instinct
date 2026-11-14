#Requires -Version 7.0
# Regression test for the how-deep-the-rabbit-hole-goes scanner.
#   evil-skill    — a classic malicious skill: every expected threat must be found;
#   evil-plugin   — a malicious plugin: hooks, MCP, marketplace, typosquatting, T21–T26;
#   evasion-skill — evasion tricks: homoglyphs, base64, line continuation, pseudo-negation, polyglot;
#   benign-skill  — legitimate patterns: nothing above LOW;
#   clean-skill   — no findings at all.
# The Ukrainian text in the samples is intentional: it exercises the scanner's Ukrainian rules.
param([string]$SecurityReportPath)
$ErrorActionPreference = 'Stop'
$scan = Join-Path $PSScriptRoot '../../skills/how-deep-the-rabbit-hole-goes/scripts/scan.ps1'
$script:failed = 0

function Invoke-Scan([string]$name) {
    $out = pwsh -NoProfile -File $scan -Path (Join-Path $PSScriptRoot $name) -Json
    $code = $LASTEXITCODE
    try { $r = $out | ConvertFrom-Json } catch { $r = $null }
    if (-not $r) { Write-Host "x ${name}: the scanner returned no JSON (exit code $code)" -ForegroundColor Red; $script:failed++; return $null }
    $r | Add-Member ExitCode $code -PassThru
}
function Assert([bool]$ok, [string]$msg) {
    if ($ok) { Write-Host "OK $msg" -ForegroundColor Green } else { Write-Host "x  $msg" -ForegroundColor Red; $script:failed++ }
}
function Has($r, [string]$threat, [string]$sev, [string]$noteLike = '*', [string]$fileLike = '*') {
    [bool]($r.Findings | Where-Object { $_.Threat -eq $threat -and $_.Severity -eq $sev -and $_.Note -like $noteLike -and $_.File -like $fileLike })
}

# ---------- evil-skill ----------
if ($evil = Invoke-Scan 'evil-skill') {
    $expected = 'T01', 'T02', 'T03', 'T04', 'T05', 'T06', 'T07', 'T08', 'T09', 'T10', 'T11', 'T12', 'T16', 'T20'
    $missing = $expected | Where-Object { $_ -notin $evil.Findings.Threat }
    Assert (-not $missing) "evil-skill: all $($expected.Count) expected threats found$(if ($missing) { " — missing $($missing -join ', ')" })"
    foreach ($note in 'outside the skill folder', 'data, not instructions', 'does not match the content', 'decode + execute') {
        Assert ([bool]($evil.Findings | Where-Object { $_.Note -like "*$note*" })) "evil-skill: has a '$note' finding"
    }
    Assert (Has $evil 'T06' 'HIGH') 'evil-skill: a negation in the H1 heading does not lower the secrets severity'
    Assert (Has $evil 'T07' 'CRITICAL' '*combination*') 'evil-skill: secrets + outbound channel = CRITICAL'
    Assert (Has $evil 'T05' 'CRITICAL' '*in decoded base64*') 'evil-skill: -EncodedCommand decoded and checked'
    Assert ($evil.ExitCode -eq 2) 'evil-skill: exit code 2'
    Assert ($evil.TreeHash -match '^[0-9a-f]{64}$' -and $evil.Inventory.Count -eq 2) 'evil-skill: tree hash and inventory present'
}

# ---------- evil-plugin ----------
if ($plugin = Invoke-Scan 'evil-plugin') {
    $expected = 'T11', 'T12', 'T13', 'T21', 'T22', 'T23', 'T24', 'T25', 'T26'
    $missing = $expected | Where-Object { $_ -notin $plugin.Findings.Threat }
    Assert (-not $missing) "evil-plugin: all $($expected.Count) expected threats found$(if ($missing) { " — missing $($missing -join ', ')" })"
    Assert (Has $plugin 'T21' 'HIGH' '*plugin hooks*' 'hooks/hooks.json') 'evil-plugin: hooks.json flagged as auto-run'
    Assert (Has $plugin 'T05' 'CRITICAL' '*' 'hooks/hooks.json') 'evil-plugin: the hook command is checked by the rules'
    Assert (Has $plugin 'T21' 'HIGH' '*MCP servers*' '.mcp.json') 'evil-plugin: .mcp.json flagged'
    Assert (Has $plugin 'T21' 'HIGH' '*dynamic command*') 'evil-plugin: dynamic !`…` command in SKILL.md'
    Assert (Has $plugin 'T11' 'MEDIUM' '*without a pinned sha*') 'evil-plugin: external source in marketplace.json'
    Assert (Has $plugin 'T12' 'HIGH' '*typosquatting*') 'evil-plugin: look-alike of a built-in skill name'
    Assert (Has $plugin 'T24' 'CRITICAL' '*API traffic*') 'evil-plugin: ANTHROPIC_BASE_URL override'
    Assert (Has $plugin 'T05' 'CRITICAL' '*reverse shell*') 'evil-plugin: reverse shell'
}

# ---------- evasion-skill ----------
if ($evasion = Invoke-Scan 'evasion-skill') {
    Assert (Has $evasion 'T01' 'CRITICAL' '*after normalization*') 'evasion-skill: homoglyph in "ignore previous instructions"'
    Assert (Has $evasion 'T05' 'CRITICAL' '*in decoded base64*') 'evasion-skill: curl | bash inside base64'
    Assert (Has $evasion 'T05' 'CRITICAL' '*' 'scripts/setup.sh') 'evasion-skill: curl | sh split by a line continuation'
    Assert ((Has $evasion 'T06' 'HIGH') -and -not ($evasion.Findings | Where-Object { $_.Threat -eq 'T06' -and $_.Note -like '*prohibition context*' })) 'evasion-skill: "do not forget" is not treated as a prohibition'
    Assert (Has $evasion 'T03' 'MEDIUM' 'without confirmation') 'evasion-skill: "without confirmation" does not lower itself'
    Assert (Has $evasion 'T02' 'CRITICAL' '*invisible*') 'evasion-skill: variation selectors (U+E0100…)'
    Assert (Has $evasion 'T02' 'MEDIUM' '*link text shows*') 'evasion-skill: link shows one domain but leads to another'
    Assert (Has $evasion 'T19' 'MEDIUM' '*after the end of the image*') 'evasion-skill: data after the end of the PNG'
    Assert (Has $evasion 'T02' 'HIGH' '*inside the image*') 'evasion-skill: instruction text inside an image'
    Assert (Has $evasion 'T19' 'HIGH' '*double extension*') 'evasion-skill: double extension'
}

# ---------- benign-skill: legitimate patterns (prohibitions, PNG, shebang, SVG comments, base64 from an API) ----------
if ($benign = Invoke-Scan 'benign-skill') {
    $noisy = @($benign.Findings | Where-Object Severity -ne 'LOW')
    $noisy | ForEach-Object { Write-Host "  $($_.Severity) $($_.Threat) $($_.File):$($_.Line) $($_.Note)" -ForegroundColor Red }
    Assert (-not $noisy -and $benign.ExitCode -eq 0) "benign-skill: nothing above LOW (LOW: $(@($benign.Findings).Count))"
}

# ---------- clean-skill ----------
if ($clean = Invoke-Scan 'clean-skill') {
    Assert (-not $clean.Findings.Count) "clean-skill: no findings$(if ($clean.Findings.Count) { " — false positives: $($clean.Findings.Threat -join ', ')" })"
}

# Additional probes are generated as inert files and removed after the scan.
pwsh -NoProfile -File (Join-Path $PSScriptRoot 'security-regressions.ps1') -ReportPath $SecurityReportPath
Assert ($LASTEXITCODE -eq 0) 'security-regressions: targeted positive, negative and robustness probes pass'

Write-Host ''
if ($script:failed) { Write-Host "Failed checks: $script:failed" -ForegroundColor Red } else { Write-Host 'All checks passed.' -ForegroundColor Green }
exit $script:failed
