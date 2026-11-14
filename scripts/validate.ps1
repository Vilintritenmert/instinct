#Requires -Version 5.1
<#
.SYNOPSIS
  Перевіряє всі скіли в skills/: наявність SKILL.md, frontmatter, name і description.
  Повертає код 1, якщо є помилки.
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

    if (-not (Test-Path $file)) { $errors += "${id}: немає SKILL.md"; continue }

    $text = Get-Content -Raw -Encoding UTF8 $file
    $m = [regex]::Match($text, '\A---\r?\n(.*?)\r?\n---', 'Singleline')
    if (-not $m.Success) { $errors += "${id}: немає frontmatter (--- ... ---) на початку файлу"; continue }

    $fm = $m.Groups[1].Value
    $name = ([regex]::Match($fm, '(?m)^name:\s*(.+?)\s*$')).Groups[1].Value
    $desc = ([regex]::Match($fm, '(?m)^description:\s*(.+?)\s*$')).Groups[1].Value

    if (-not $name) { $errors += "${id}: немає поля name" }
    elseif ($name -ne $dir.Name) { $errors += "${id}: name '$name' не збігається з назвою папки" }
    elseif ($name -cnotmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $name.Length -gt 64) { $errors += "${id}: name не kebab-case або довший за 64" }

    if (-not $desc) { $errors += "${id}: немає поля description" }
    elseif ($desc.Length -gt 1024) { $errors += "${id}: description довший за 1024 ($($desc.Length))" }
    elseif ($desc -match '\{\{|<.+>') { $errors += "${id}: description містить незаповнений плейсхолдер" }

    if ($text -match '\{\{NAME\}\}|\{\{DESCRIPTION\}\}') { $errors += "${id}: лишилися плейсхолдери шаблону" }
}

if ($errors) {
    $errors | ForEach-Object { Write-Host "✗ $_" -ForegroundColor Red }
    Write-Host "$($errors.Count) помилок у $count скілах." -ForegroundColor Red
    exit 1
}
Write-Host "✓ Скілів: $count, помилок немає." -ForegroundColor Green
