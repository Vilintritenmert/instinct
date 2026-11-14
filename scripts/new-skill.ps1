#Requires -Version 5.1
<#
.SYNOPSIS
  Створює новий скіл у skills/<Name>/SKILL.md із шаблону.
.EXAMPLE
  ./scripts/new-skill.ps1 -Name my-skill -Description "Що робить і коли вмикати."
#>
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Description
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ($Name -cnotmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $Name.Length -gt 64) {
    throw "Name має бути kebab-case (a-z, 0-9, дефіси), до 64 символів: '$Name'"
}
if ($Description.Length -gt 1024) {
    throw "Description довший за 1024 символи ($($Description.Length))."
}

$dir = Join-Path $root "skills/$Name"
if (Test-Path $dir) { throw "Скіл '$Name' вже існує: $dir" }

$template = Get-Content -Raw -Encoding UTF8 (Join-Path $root 'templates/SKILL.template.md')
$content = $template.Replace('{{NAME}}', $Name).Replace('{{DESCRIPTION}}', $Description)

New-Item -ItemType Directory -Force $dir | Out-Null
[System.IO.File]::WriteAllText((Join-Path $dir 'SKILL.md'), $content, [System.Text.UTF8Encoding]::new($false))

Write-Host "Створено skills/$Name/SKILL.md"
