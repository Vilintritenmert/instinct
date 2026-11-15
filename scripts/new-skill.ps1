#Requires -Version 5.1
<#
.SYNOPSIS
  Creates a new skill at skills/<Name>/SKILL.md from the template.
.EXAMPLE
  ./scripts/new-skill.ps1 -Name my-skill -Description "What the skill does and when to use it."
#>
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Description
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ($Name -cnotmatch '^[a-z0-9]+(-[a-z0-9]+)*$' -or $Name.Length -gt 64) {
    throw "Name must be kebab-case (a-z, 0-9, hyphens), at most 64 characters: '$Name'"
}
if ($Description.Length -gt 1024) {
    throw "Description is longer than 1024 characters ($($Description.Length))."
}

$dir = Join-Path $root "skills/$Name"
if (Test-Path $dir) { throw "Skill '$Name' already exists: $dir" }

$template = Get-Content -Raw -Encoding UTF8 (Join-Path $root 'templates/SKILL.template.md')
$content = $template.Replace('{{NAME}}', $Name).Replace('{{DESCRIPTION}}', $Description)

New-Item -ItemType Directory -Force $dir | Out-Null
[System.IO.File]::WriteAllText((Join-Path $dir 'SKILL.md'), $content, [System.Text.UTF8Encoding]::new($false))

Write-Host "Created skills/$Name/SKILL.md"
