param([string]$Version = '1.0.0.0')

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if ($Version -notmatch '^[1-9][0-9]*\.[0-9]+\.[0-9]+\.0$') {
    throw 'Use uma versão no formato 1.0.0.0; o último número deve ser zero.'
}

$app = Join-Path $PSScriptRoot 'dist\FirawCallMonitor'
if (-not (Test-Path -LiteralPath (Join-Path $app 'FirawCallMonitor.exe'))) {
    throw 'Execute build.ps1 antes de build_msix.ps1.'
}

$stage = Join-Path $PSScriptRoot 'build\msix-stage'
$resolvedRoot = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
$resolvedStage = [IO.Path]::GetFullPath($stage)
if (-not $resolvedStage.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Pasta temporária fora do projeto.'
}
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $stage 'Assets') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $app 'FirawCallMonitor.exe') -Destination $stage
Copy-Item -LiteralPath (Join-Path $app '_internal') -Destination $stage -Recurse

$python = Join-Path $PSScriptRoot '.build-venv\Scripts\python.exe'
& $python prepare_msix_assets.py
if ($LASTEXITCODE -ne 0) { throw 'Falha ao preparar ícones do MSIX.' }

$manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap uap10 rescap">
  <Identity Name="Firawynix.Firaw-MonitordeChamadasparaTeams"
            Publisher="CN=1FDE3668-C222-4506-AFE6-E2E425EAECD8"
            Version="__VERSION__" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Firaw - Monitor de Chamadas para Teams</DisplayName>
    <PublisherDisplayName>Firawynix</PublisherDisplayName>
    <Description>Diagnóstico local de chamadas do Microsoft Teams.</Description>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Resources><Resource Language="pt-BR" /></Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
  <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
  <Applications>
    <Application Id="FirawCallMonitor" Executable="FirawCallMonitor.exe"
                 uap10:RuntimeBehavior="packagedClassicApp" uap10:TrustLevel="mediumIL">
      <uap:VisualElements DisplayName="Firaw - Monitor de Chamadas para Teams"
                          Description="Diagnóstico local de chamadas do Microsoft Teams"
                          Square150x150Logo="Assets\Square150x150Logo.png"
                          Square44x44Logo="Assets\Square44x44Logo.png"
                          BackgroundColor="#101827" />
    </Application>
  </Applications>
</Package>
'@
$manifest.Replace('__VERSION__', $Version) | Set-Content -LiteralPath (Join-Path $stage 'AppxManifest.xml') -Encoding utf8

$sdkBin = Get-ChildItem -LiteralPath "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Directory |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'x64\makeappx.exe') } |
    Sort-Object Name -Descending | Select-Object -First 1
if (-not $sdkBin) { throw 'Windows SDK com MakeAppx.exe não encontrado.' }
$makeappx = Join-Path $sdkBin.FullName 'x64\makeappx.exe'
$output = Join-Path $PSScriptRoot "dist\FirawCallMonitor_$($Version)_x64.msix"
& $makeappx pack /d $stage /p $output /o
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar o MSIX.' }
Write-Host "Pacote gerado: $output"
