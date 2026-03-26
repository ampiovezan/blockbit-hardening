$ErrorActionPreference = "Continue"

# =========================
# CONFIG
# =========================
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = "$env:SystemRoot\Temp\Blockbit_Hardening_$timestamp.log"

function Log {
    param([string]$msg)
    $line = "$(Get-Date -Format 'HH:mm:ss') - $msg"
    $line | Out-File -FilePath $logPath -Append -Encoding utf8
}

Log "==== INICIO HARDENING ===="

# =========================
# CONTEXT CHECK
# =========================
try {
    $isDomain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    Log "Maquina em dominio: $isDomain"
} catch {
    Log "Erro ao verificar dominio"
    $isDomain = $false
}

# =========================
# REGISTRY HARDENING
# =========================
try {
    Log "Aplicando registry hardening..."

    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force | Out-Null

    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "EnableLUA" -Value 1 -PropertyType DWord -Force | Out-Null

    Log "Registry OK"
} catch {
    Log "Erro registry"
}

# =========================
# SERVICES HARDENING
# =========================
function Disable-ServiceSafe {
    param($name)

    try {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name $name -StartupType Disabled -ErrorAction SilentlyContinue
            Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
            Log "Servico $name desabilitado"
        } else {
            Log "Servico $name inexistente (skip)"
        }
    } catch {
        Log "Erro ao tratar servico $name"
    }
}

Log "Aplicando hardening de servicos..."

Disable-ServiceSafe "RemoteRegistry"
Disable-ServiceSafe "XboxGipSvc"
Disable-ServiceSafe "XblAuthManager"
Disable-ServiceSafe "XblGameSave"

# =========================
# FIREWALL
# =========================
try {
    Log "Configurando firewall..."

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

    Log "Firewall OK"
} catch {
    Log "Erro firewall"
}

# =========================
# DEFENDER
# =========================
try {
    Log "Configurando Defender..."

    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableScriptScanning $false

    Log "Defender OK"
} catch {
    Log "Erro Defender"
}

# =========================
# AUDIT POLICY
# =========================
try {
    Log "Configurando auditoria..."

    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null

    Log "Audit OK"
} catch {
    Log "Erro auditoria"
}

# =========================
# MARKER REGISTRY
# =========================
try {
    New-Item -Path "HKLM:\Software\Blockbit\Hardening" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Blockbit\Hardening" `
        -Name "FullApplied" -Value 1 -PropertyType DWord -Force | Out-Null

    Log "Marker aplicado"
} catch {
    Log "Erro marker"
}

# =========================
# FINAL
# =========================
Log "==== FIM HARDENING ===="

exit 0
