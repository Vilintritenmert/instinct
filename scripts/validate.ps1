#Requires -Version 5.1
<#
.SYNOPSIS
  Checks every skill in skills/: SKILL.md exists, has frontmatter, name and description.
  Exits with code 1 if there are errors.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$skillsDir = Join-Path $root 'skills'
$errors = @()
$count = 0

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

if ($errors) {
    $errors | ForEach-Object { Write-Host "x $_" -ForegroundColor Red }
    Write-Host "$($errors.Count) error(s) in $count skill(s)." -ForegroundColor Red
    exit 1
}
Write-Host "OK: $count skill(s), no errors." -ForegroundColor Green
