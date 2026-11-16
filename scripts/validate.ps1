#Requires -Version 5.1
<#
.SYNOPSIS
  Checks portable/host plugin manifests and every skill's frontmatter.
  Exits with code 1 if there are errors.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$skillsDir = Join-Path $root 'skills'
$errors = @()
$count = 0

# Portable clients discover skills/ at a fixed location. Host overlays describe
# the same package and must not drift when releasing a new version.
$manifestPaths = @('plugin.json', '.claude-plugin/plugin.json', '.codex-plugin/plugin.json')
$manifests = @{}
foreach ($relative in $manifestPaths) {
    try {
        $manifest = Get-Content -LiteralPath (Join-Path $root $relative) -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not ($manifest -is [pscustomobject])) { throw 'expected a JSON object' }
        foreach ($key in @('name', 'version', 'description', 'license')) {
            if (-not ($manifest.$key -is [string]) -or [string]::IsNullOrWhiteSpace($manifest.$key)) {
                $errors += "${relative}: $key must be a nonblank string"
            }
        }
        $manifests[$relative] = $manifest
    } catch {
        $errors += "${relative}: cannot read plugin manifest: $_"
    }
}
$portable = $manifests['plugin.json']
if ($portable) {
    if ($portable.'$schema' -cne 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json') {
        $errors += 'plugin.json: missing Agent Plugins 1.0 schema declaration'
    }
    if ($portable.name -cnotmatch '^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -or $portable.name.Length -gt 64) {
        $errors += 'plugin.json: invalid portable plugin name'
    }
    if ($portable.version -cnotmatch '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$') {
        $errors += 'plugin.json: version must use semantic versioning'
    }
    $portableKeys = @('$schema', 'name', 'version', 'description', 'author', 'homepage', 'repository', 'license', 'keywords', 'extensions')
    foreach ($key in $portable.PSObject.Properties.Name) {
        if ($key -cnotin $portableKeys) { $errors += "plugin.json: unsupported portable field '$key'" }
    }
    foreach ($relative in $manifestPaths | Select-Object -Skip 1) {
        $overlay = $manifests[$relative]
        if (-not $overlay) { continue }
        foreach ($key in @('name', 'version', 'description', 'license')) {
            if ($overlay.$key -cne $portable.$key) { $errors += "${relative}: $key differs from plugin.json" }
        }
    }
}
if ($manifests['.codex-plugin/plugin.json'] -and $manifests['.codex-plugin/plugin.json'].skills -cne './skills') {
    $errors += '.codex-plugin/plugin.json: skills must point to ./skills'
}

foreach ($dir in Get-ChildItem -Directory $skillsDir -ErrorAction SilentlyContinue) {
    $count++
    $file = Join-Path $dir.FullName 'SKILL.md'
    $id = "skills/$($dir.Name)"

    if (-not (Test-Path $file)) { $errors += "${id}: no SKILL.md"; continue }

    $text = Get-Content -Raw -Encoding UTF8 $file
    $m = [regex]::Match($text, '\A---\r?\n(.*?)\r?\n---', 'Singleline')
    if (-not $m.Success) { $errors += "${id}: no frontmatter (--- ... ---) at the start of the file"; continue }

    $fm = $m.Groups[1].Value
    $name = ([regex]::Match($fm, '(?m)^name:\s*(.+?)\s*$')).Groups[1].Value
    $desc = ([regex]::Match($fm, '(?m)^description:\s*(.+?)\s*$')).Groups[1].Value

    if (-not $name) { $errors += "${id}: no name field" }
    elseif ($name -ne $dir.Name) { $errors += "${id}: name '$name' does not match the folder name" }
    elseif ($name -cnotmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $name.Length -gt 64) { $errors += "${id}: name is not kebab-case or is longer than 64" }

    if (-not $desc) { $errors += "${id}: no description field" }
    elseif ($desc.Length -gt 1024) { $errors += "${id}: description is longer than 1024 ($($desc.Length))" }
    elseif ($desc -match '\{\{|<.+>') { $errors += "${id}: description contains an unfilled placeholder" }

    if ($text -match '\{\{NAME\}\}|\{\{DESCRIPTION\}\}') { $errors += "${id}: template placeholders left in the file" }
}

if ($count -eq 0) { $errors += 'skills/: no skills found' }

if ($errors) {
    $errors | ForEach-Object { Write-Host "x $_" -ForegroundColor Red }
    Write-Host "$($errors.Count) error(s) in $count skill(s)." -ForegroundColor Red
    exit 1
}
Write-Host "OK: $($manifestPaths.Count) plugin manifests, $count skill(s), no errors." -ForegroundColor Green
