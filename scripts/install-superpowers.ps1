$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$vendorRoot = Join-Path $projectRoot '.agents/vendor/superpowers'
$skillsRoot = Join-Path $projectRoot '.agents/skills'
$version = 'v7.0.2'

if (-not (Test-Path -LiteralPath $vendorRoot)) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $vendorRoot) | Out-Null
    git clone --depth 1 --branch $version https://github.com/obra/superpowers.git $vendorRoot
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao baixar Superpowers.' }
}

$sourceSkills = Join-Path $vendorRoot 'skills'
if (-not (Test-Path -LiteralPath $sourceSkills)) {
    throw "Skills não encontradas em $sourceSkills"
}
$installedVersion = git -C $vendorRoot describe --tags --exact-match 2>$null
if ($LASTEXITCODE -ne 0 -or $installedVersion -ne $version) {
    throw "A cópia local precisa estar no tag $version."
}

New-Item -ItemType Directory -Force -Path $skillsRoot | Out-Null
foreach ($skill in Get-ChildItem -LiteralPath $sourceSkills -Directory) {
    $link = Join-Path $skillsRoot $skill.Name
    if (-not (Test-Path -LiteralPath $link)) {
        New-Item -ItemType Junction -Path $link -Target $skill.FullName | Out-Null
    }
    $installed = Get-Item -LiteralPath $link -Force
    if ($installed.LinkType -ne 'Junction' -or $installed.Target -ne $skill.FullName) {
        throw "O caminho $link não aponta para a cópia local esperada."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $link 'SKILL.md'))) {
        throw "Skill indisponível em $link"
    }
}

Write-Output "Superpowers $version disponível somente em $projectRoot. Abra uma nova sessão do Codex."
