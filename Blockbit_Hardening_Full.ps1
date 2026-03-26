$ErrorActionPreference = 'Continue'

$global:CountFail = 0
$global:CountOK = 0

$log = "$env:SystemRoot\Temp\Blockbit_Hardening_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"

function Log {
    param($m)
    "$((Get-Date).ToString('HH:mm:ss')) - $m" | Out-File -Append -FilePath $log
}

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [int]$Value
    )
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
        Log "[OK] REG $Path\$Name = $Value"
        $global:CountOK++
    } catch {
        Log "[FAIL] REG $Path\$Name"
        $global:CountFail++
    }
}

function Disable-ServiceSafe {
    param([string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $svc) {
            Log "[SKIP] Service $Name nao existe"
            return
        }

        Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue

        Log "[OK] Service $Name desabilitado"
        $global:CountOK++
    } catch {
        Log "[FAIL] Service $Name"
        $global:CountFail++
    }
}

Log "Inicio do hardening"

# =========================
# EXEMPLOS DE HARDENING
# =========================

# Exemplo registro seguro
Set-RegValue -Path "HKLM:\Software\BlockbitTest" -Name "HardeningOK" -Value 1

# Exemplo política real (ajustar conforme necessário)
Set-RegValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

# Serviço exemplo
Disable-ServiceSafe -Name "RemoteRegistry"

# =========================
# RESULTADO FINAL
# =========================

if ($global:CountFail -eq 0) {
    try {
        if (!(Test-Path "HKLM:\Software\Blockbit\Hardening")) {
            New-Item -Path "HKLM:\Software\Blockbit\Hardening" -Force | Out-Null
        }

        New-ItemProperty -Path "HKLM:\Software\Blockbit\Hardening" -Name "FullApplied" -Value 1 -PropertyType DWord -Force | Out-Null
        Log "[OK] Hardening completo aplicado"
    } catch {
        Log "[FAIL] Nao conseguiu gravar marker final"
    }
} else {
    Log "[WARN] Hardening com falhas: $global:CountFail"
}

Log "Fim do hardening"
exit $global:CountFail
