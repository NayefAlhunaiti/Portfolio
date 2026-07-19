$ErrorActionPreference = "Stop"

Write-Host "IOC Nexus Windows setup" -ForegroundColor Cyan

if (-not (Test-Path ".\pyproject.toml")) {
    Write-Error "pyproject.toml was not found. Open PowerShell inside the project folder, then run this script again."
}

$pythonCommand = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCommand = "py"
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCommand = "python"
} else {
    Write-Error "Python 3.11 or newer was not found. Install Python, reopen PowerShell, and rerun this script."
}

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    & $pythonCommand -m venv .venv
}

Write-Host "Installing dependencies and the local package..."
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
& ".\.venv\Scripts\python.exe" -m pip install -r requirements-ml.txt
& ".\.venv\Scripts\python.exe" -m pip install -e .

Write-Host "Verifying package import..."
& ".\.venv\Scripts\python.exe" -c "import ioc_nexus; print('ioc_nexus installed successfully:', ioc_nexus.__version__)"

Write-Host "Running automated tests..."
& ".\.venv\Scripts\python.exe" -m pytest

Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Run the demo with:"
Write-Host ".\.venv\Scripts\python.exe -m ioc_nexus.cli --incident examples\incident_external_ip.json --mock-vt"
