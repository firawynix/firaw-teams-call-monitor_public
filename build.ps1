param([switch]$SkipDependencies)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$python = Join-Path $PSScriptRoot '.build-venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    py -3.13 -m venv .build-venv
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.13 não está instalado.' }
}
if (-not $SkipDependencies) {
    & $python -m pip install -r requirements.txt 'pyinstaller>=6.0,<7' 'pillow>=12,<13'
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar dependências.' }
}
& $python -m PyInstaller --noconfirm --clean --onedir --windowed --name FirawCallMonitor --icon assets\icon.ico --add-data 'assets\icon-64.png;assets' --collect-all pycaw --collect-all comtypes monitor.py
if ($LASTEXITCODE -ne 0) { throw 'Falha ao gerar o aplicativo.' }
Write-Host "Aplicativo gerado em: $(Join-Path $PSScriptRoot 'dist\FirawCallMonitor')"
