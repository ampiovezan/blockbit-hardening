$ErrorActionPreference = 'Continue'

# ==============================================================================
# Blockbit Hardening - Windows 10/11
# Execucao remota via Blockbit XDR / Wazuh
# Log local apenas
# ==============================================================================

$global:CountOK = 0
$global:CountFail = 0
$global:CountSkip = 0
$global:CountWarn = 0
$global:FailedItems = New-Object System.Collections.Generic.List[string]
$global:SkippedItems = New-Object System.Collections.Generic.List[string]

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logDir = Join-Path $env:SystemRoot 'Temp'
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

$global:RunLog = Join-Path $logDir "Blockbit_Hardening_win10_11_$timestamp.log"
New-Item -Path $global:RunLog -ItemType File -Force | Out-Null

function Write-RunLog {
    param(
        [string]$Level,
        [string]$Id,
        [string]$Message
    )

    $line = "[{0}] [{1}] [{2}] {3}" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Id, $Message
    Add-Content -Path $global:RunLog -Value $line -Encoding UTF8

    switch ($Level.ToUpperInvariant()) {
        'OK'   { $global:CountOK++ }
        'FAIL' {
            $global:CountFail++
            $global:FailedItems.Add($Id)
        }
        'SKIP' {
            $global:CountSkip++
            $global:SkippedItems.Add($Id)
        }
        'WARN' { $global:CountWarn++ }
    }
}

function Test-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-RegistryKey {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-RegValue {
    param(
        [string]$Id,
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type,
        [string]$OkMessage,
        [string]$FailMessage
    )
    try {
        Ensure-RegistryKey -Path $Path

        $existing = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        } else {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }

        Write-RunLog 'OK' $Id $OkMessage
    } catch {
        Write-RunLog 'FAIL' $Id ($FailMessage + " | " + $_.Exception.Message)
    }
}

function Invoke-NetAccounts {
    param(
        [string]$Id,
        [string]$Arguments,
        [string]$OkMessage,
        [string]$FailMessage
    )
    try {
        $proc = Start-Process -FilePath "$env:SystemRoot\System32\net.exe" -ArgumentList "accounts $Arguments" -WindowStyle Hidden -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-RunLog 'OK' $Id $OkMessage
        } else {
            Write-RunLog 'FAIL' $Id ($FailMessage + " | ExitCode=" + $proc.ExitCode)
        }
    } catch {
        Write-RunLog 'FAIL' $Id ($FailMessage + " | " + $_.Exception.Message)
    }
}

function Disable-ServiceStartupSafe {
    param(
        [string]$Id,
        [string]$ServiceName,
        [string]$OkMessage,
        [string]$FailMessage
    )
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        if (-not $svc) {
            Write-RunLog 'SKIP' $Id "servico $ServiceName nao encontrado no sistema"
            return
        }

        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name Start -Value 4 -Type DWord -Force

        try {
            if ($svc.State -eq 'Running') {
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            }
        } catch {}

        Write-RunLog 'OK' $Id $OkMessage
    } catch {
        Write-RunLog 'FAIL' $Id ($FailMessage + " | " + $_.Exception.Message)
    }
}

function Set-AuditPolicyGuid {
    param(
        [string]$Id,
        [string]$Guid,
        [string]$SuccessMode,
        [string]$FailureMode,
        [string]$DisplayName
    )
    try {
        $get = Start-Process -FilePath "$env:SystemRoot\System32\auditpol.exe" -ArgumentList "/get /subcategory:$Guid" -WindowStyle Hidden -Wait -PassThru
        if ($get.ExitCode -ne 0) {
            Write-RunLog 'SKIP' $Id "subcategoria de auditoria $DisplayName (GUID $Guid) nao disponivel"
            return
        }

        $set = Start-Process -FilePath "$env:SystemRoot\System32\auditpol.exe" -ArgumentList "/set /subcategory:$Guid /success:$SuccessMode /failure:$FailureMode" -WindowStyle Hidden -Wait -PassThru
        if ($set.ExitCode -eq 0) {
            Write-RunLog 'OK' $Id "subcategoria $DisplayName configurada (success:$SuccessMode failure:$FailureMode)"
        } else {
            Write-RunLog 'FAIL' $Id "auditpol retornou erro para $DisplayName (GUID $Guid)"
        }
    } catch {
        Write-RunLog 'FAIL' $Id ("falha ao configurar auditoria $DisplayName | " + $_.Exception.Message)
    }
}

function Disable-AndRenameGuest {
    try {
        $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
        if (-not $guest) {
            Write-RunLog 'SKIP' 'disable_guest_account' 'conta interna RID-501 nao localizada'
            Write-RunLog 'SKIP' 'rename_guest_account' 'rename ignorado pois conta RID-501 nao foi localizada'
            return
        }

        $guestName = $guest.Name

        try {
            $localGuest = Get-LocalUser -Name $guestName -ErrorAction Stop
            if ($localGuest.Enabled) {
                Disable-LocalUser -Name $guestName -ErrorAction Stop
                Write-RunLog 'OK' 'disable_guest_account' "conta $guestName (RID-501) desabilitada com sucesso"
            } else {
                Write-RunLog 'OK' 'disable_guest_account' "conta $guestName (RID-501) ja estava desabilitada - nenhuma acao necessaria"
            }
        } catch {
            Write-RunLog 'SKIP' 'disable_guest_account' "nao foi possivel determinar ou alterar status da conta $guestName (RID-501)"
        }

        if ($guestName -ieq 'disabled_user') {
            Write-RunLog 'OK' 'rename_guest_account' "conta RID-501 ja possui o nome 'disabled_user' - nenhuma acao necessaria"
            return
        }

        try {
            if (Get-Command Rename-LocalUser -ErrorAction SilentlyContinue) {
                Rename-LocalUser -Name $guestName -NewName 'disabled_user' -ErrorAction Stop
                Write-RunLog 'OK' 'rename_guest_account' "conta $guestName (RID-501) renomeada para 'disabled_user'"
            } else {
                Write-RunLog 'SKIP' 'rename_guest_account' "Rename-LocalUser nao disponivel neste sistema"
            }
        } catch {
            Write-RunLog 'FAIL' 'rename_guest_account' ("falha ao renomear conta $guestName (RID-501) | " + $_.Exception.Message)
        }
    } catch {
        Write-RunLog 'FAIL' 'guest_account_handling' ("falha geral no tratamento da conta Guest | " + $_.Exception.Message)
    }
}

function Test-DefenderAvailable {
    try {
        Get-MpComputerStatus -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Enable-DefenderPreference {
    param(
        [string]$Id,
        [scriptblock]$Script,
        [string]$OkMessage,
        [string]$FailMessage
    )
    if (-not (Test-DefenderAvailable)) {
        Write-RunLog 'SKIP' $Id 'Defender nao disponivel ou gerenciado por outro produto'
        return
    }
    try {
        & $Script
        Write-RunLog 'OK' $Id $OkMessage
    } catch {
        Write-RunLog 'FAIL' $Id ($FailMessage + " | " + $_.Exception.Message)
    }
}

function Set-MarkerIfSuccess {
    try {
        Ensure-RegistryKey -Path 'HKLM:\Software\Blockbit\Hardening'
        $existing = Get-ItemProperty -Path 'HKLM:\Software\Blockbit\Hardening' -Name 'FullApplied' -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            Set-ItemProperty -Path 'HKLM:\Software\Blockbit\Hardening' -Name 'FullApplied' -Value 1 -Type DWord -ErrorAction Stop
        } else {
            New-ItemProperty -Path 'HKLM:\Software\Blockbit\Hardening' -Name 'FullApplied' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        }
        Write-RunLog 'OK' 'hardening_marker' 'marker FullApplied=1 gravado com sucesso'
    } catch {
        Write-RunLog 'FAIL' 'hardening_marker' ('falha ao gravar marker FullApplied | ' + $_.Exception.Message)
    }
}

Write-RunLog 'INFO' 'iniciando' 'Blockbit Hardening - Windows 10/11'
Write-RunLog 'INFO' 'iniciando' "Log detalhado: $global:RunLog"

if (-not (Test-Administrator)) {
    Write-RunLog 'FAIL' 'precheck_privilegios' 'execucao sem privilegios administrativos - abortando'
    exit 1
}
Write-RunLog 'OK' 'precheck_privilegios' 'privilegios administrativos confirmados'

Write-RunLog 'INFO' 'detect_os' 'identificando sistema operacional e ambiente de rede'
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
    $caption = $os.Caption
    $version = $os.Version
    $arch = $os.OSArchitecture
} catch {
    Write-RunLog 'FAIL' 'detect_os' ('nao foi possivel identificar o sistema operacional | ' + $_.Exception.Message)
    exit 1
}

$isWin10 = $caption -match 'Windows 10'
$isWin11 = $caption -match 'Windows 11'
if (-not ($isWin10 -or $isWin11)) {
    Write-RunLog 'FAIL' 'detect_os' "sistema nao suportado: $caption - script abortado"
    exit 1
}

Write-RunLog 'INFO' 'detect_os' "SO: $caption - Versao: $version - Build: $build - Arch: $arch"

$isDomain = $false
$domainName = $null
try {
    $isDomain = [bool]$cs.PartOfDomain
    $domainName = $cs.Domain
} catch {}

if ($isDomain) {
    Write-RunLog 'WARN' 'detect_os' "maquina ingressada em dominio: $domainName - politicas de senha serao ignoradas (gerenciadas pelo DC)"
} else {
    Write-RunLog 'INFO' 'detect_os' 'maquina standalone (workgroup) - politicas locais serao aplicadas'
}

if ($isWin10) { Write-RunLog 'OK' 'detect_os' "Windows 10 identificado - build $build" }
if ($isWin11) { Write-RunLog 'OK' 'detect_os' "Windows 11 identificado - build $build" }

Write-RunLog 'INFO' 'account_policies' 'iniciando secao de politicas de conta'
if ($isDomain) {
    Write-RunLog 'SKIP' 'account_policies_password' "maquina em dominio $domainName - politica de senha gerenciada pelo DC - nao aplicado localmente para evitar conflito com GPO"
    Write-RunLog 'SKIP' 'account_policies_lockout' "maquina em dominio $domainName - politica de bloqueio gerenciada pelo DC - nao aplicado localmente para evitar conflito com GPO"
} else {
    Invoke-NetAccounts 'set_min_password_length' '/minpwlen:14' 'comprimento minimo configurado para 14 caracteres' 'falha ao configurar comprimento minimo'
    Invoke-NetAccounts 'set_password_history' '/uniquepw:24' 'historico configurado para 24 senhas anteriores' 'falha ao configurar historico de senha'
    Invoke-NetAccounts 'set_max_password_age' '/maxpwage:180' 'idade maxima configurada para 180 dias' 'falha ao configurar idade maxima'
    Invoke-NetAccounts 'set_min_password_age' '/minpwage:1' 'idade minima configurada para 1 dia' 'falha ao configurar idade minima'
    Set-RegValue 'set_relax_min_password_length_limits' 'HKLM:\System\CurrentControlSet\Control\SAM' 'RelaxMinimumPasswordLengthLimits' 1 DWord 'RelaxMinimumPasswordLengthLimits=1 configurado' 'falha ao configurar RelaxMinimumPasswordLengthLimits'
    Invoke-NetAccounts 'set_lockout_threshold' '/lockoutthreshold:5' 'limiar de bloqueio configurado para 5 tentativas' 'falha ao configurar limiar de bloqueio'
    Invoke-NetAccounts 'set_lockout_duration' '/lockoutduration:15' 'duracao do bloqueio configurada para 15 minutos' 'falha ao configurar duracao do bloqueio'
    Invoke-NetAccounts 'set_lockout_window' '/lockoutwindow:15' 'janela de redefinicao configurada para 15 minutos' 'falha ao configurar janela de redefinicao'
}

Disable-AndRenameGuest

Write-RunLog 'INFO' 'security_options' 'iniciando security options'
Set-RegValue 'set_disablecad' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD' 0 DWord 'CTRL+ALT+DEL habilitado como requisito de logon' 'falha ao configurar DisableCAD'
Set-RegValue 'set_dontdisplaylastusername' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'DontDisplayLastUserName' 1 DWord 'ultimo usuario nao sera exibido na tela de logon' 'falha ao configurar DontDisplayLastUserName'
Set-RegValue 'set_maxdevicepasswordfailedattempts' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'MaxDevicePasswordFailedAttempts' 10 DWord 'bloqueio de conta de maquina configurado para 10 tentativas' 'falha ao configurar MaxDevicePasswordFailedAttempts'
Set-RegValue 'set_legal_notice_text' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'LegalNoticeText' 'This system is for authorized use only. Activities are monitored and logged.' String 'banner de aviso legal (texto) configurado' 'falha ao configurar LegalNoticeText'
Set-RegValue 'set_legal_notice_caption' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'LegalNoticeCaption' 'Authorized Access Warning' String 'banner de aviso legal (titulo) configurado' 'falha ao configurar LegalNoticeCaption'
Set-RegValue 'set_inactivity_timeout' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs' 900 DWord 'timeout de inatividade configurado para 900 segundos (15 min)' 'falha ao configurar InactivityTimeoutSecs'
Set-RegValue 'set_uac_standard_user_prompt' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorUser' 0 DWord 'UAC configurado para negar elevacao automaticamente para usuarios padrao' 'falha ao configurar ConsentPromptBehaviorUser'
Set-RegValue 'set_smartcard_removal' 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ScRemoveOption' 1 DWord 'remocao de smart card configurada para bloquear estacao de trabalho' 'falha ao configurar ScRemoveOption'
Set-RegValue 'set_sce_no_apply_legacy_audit' 'HKLM:\System\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1 DWord 'subcategorias de auditoria avancada habilitadas para sobrescrever categorias legadas' 'falha ao configurar SCENoApplyLegacyAuditPolicy'
Set-RegValue 'set_cached_logons_count' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' '4' String 'logons em cache limitados a 4 (reduz exposicao de credenciais offline)' 'falha ao configurar CachedLogonsCount'

Write-RunLog 'INFO' 'network_auth' 'iniciando configuracoes de autenticacao de rede'
Set-RegValue 'set_allow_insecure_guest_auth' 'HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0 DWord 'autenticacao de convidado insegura desabilitada (previne acesso SMB anonimo)' 'falha ao configurar AllowInsecureGuestAuth'
Set-RegValue 'set_restrict_anonymous' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1 DWord 'enumeracao anonima de SAM e compartilhamentos restringida' 'falha ao configurar RestrictAnonymous'
Set-RegValue 'set_disable_domain_creds' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'DisableDomainCreds' 1 DWord 'armazenamento de credenciais de rede no Credential Manager desabilitado' 'falha ao configurar DisableDomainCreds'
Set-RegValue 'set_use_machine_id' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'UseMachineId' 1 DWord 'identidade de maquina habilitada para autenticacao NTLM do sistema local' 'falha ao configurar UseMachineId'
Set-RegValue 'set_kerberos_supported_encryption' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' 'SupportedEncryptionTypes' 2147483640 DWord 'tipos de criptografia Kerberos configurados (AES128+AES256+Future)' 'falha ao configurar SupportedEncryptionTypes'
Set-RegValue 'set_lm_compatibility' 'HKLM:\System\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5 DWord 'autenticacao configurada para NTLMv2 apenas (nivel 5 - rejeita LM e NTLMv1)' 'falha ao configurar LmCompatibilityLevel'
Set-RegValue 'set_ntlm_min_client_sec' 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinClientSec' 537395200 DWord 'seguranca minima de sessao NTLM para clientes configurada (NTLMv2+128bit)' 'falha ao configurar NtlmMinClientSec'
Set-RegValue 'set_ntlm_min_server_sec' 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' 'NtlmMinServerSec' 537395200 DWord 'seguranca minima de sessao NTLM para servidores configurada (NTLMv2+128bit)' 'falha ao configurar NtlmMinServerSec'
Set-RegValue 'set_audit_receiving_ntlm' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'AuditReceivingNTLMTraffic' 2 DWord 'auditoria de trafego NTLM de entrada habilitada (modo: Enable auditing for all accounts)' 'falha ao configurar AuditReceivingNTLMTraffic'
Set-RegValue 'set_restrict_sending_ntlm' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' 'RestrictSendingNTLMTraffic' 1 DWord 'auditoria de trafego NTLM de saida habilitada (modo: Audit all)' 'falha ao configurar RestrictSendingNTLMTraffic'

Write-RunLog 'INFO' 'uac' 'iniciando configuracoes de UAC'
Set-RegValue 'set_filter_administrator_token' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'FilterAdministratorToken' 1 DWord 'Admin Approval Mode habilitado para conta Administrator interna' 'falha ao configurar FilterAdministratorToken'
Set-RegValue 'set_uac_admin_prompt' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 2 DWord 'prompt de elevacao para admins configurado na area de trabalho segura' 'falha ao configurar ConsentPromptBehaviorAdmin'
Set-RegValue 'set_enable_lua' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 1 DWord 'UAC habilitado (todos os admins executam no modo de aprovacao de admin)' 'falha ao configurar EnableLUA'
Set-RegValue 'set_prompt_on_secure_desktop' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 1 DWord 'secure desktop habilitado para prompts de elevacao UAC' 'falha ao configurar PromptOnSecureDesktop'
Set-RegValue 'set_enable_installer_detection' 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableInstallerDetection' 1 DWord 'deteccao automatica de instaladores habilitada' 'falha ao configurar EnableInstallerDetection'

Write-RunLog 'INFO' 'services' 'desabilitando servicos desnecessarios de baixo risco'
Disable-ServiceStartupSafe 'disable_service_remoteregistry' 'RemoteRegistry' 'RemoteRegistry desabilitado (previne edicao remota do registro)' 'falha ao desabilitar RemoteRegistry'
Disable-ServiceStartupSafe 'disable_service_ssdpsrv' 'SSDPSRV' 'SSDPSRV (SSDP Discovery) desabilitado (reduz exposicao UPnP)' 'falha ao desabilitar SSDPSRV'
Disable-ServiceStartupSafe 'disable_service_upnphost' 'upnphost' 'UPnP Device Host desabilitado (reduz exposicao a dispositivos nao gerenciados)' 'falha ao desabilitar upnphost'
Disable-ServiceStartupSafe 'disable_service_mapsbroker' 'MapsBroker' 'Downloaded Maps Manager desabilitado (nao necessario em endpoints corporativos)' 'falha ao desabilitar MapsBroker'
Disable-ServiceStartupSafe 'disable_service_lfsvc' 'lfsvc' 'Geolocation Service desabilitado (nao necessario em endpoints corporativos)' 'falha ao desabilitar lfsvc'
Disable-ServiceStartupSafe 'disable_service_wmpnetworksvc' 'WMPNetworkSvc' 'Windows Media Player Network Sharing desabilitado' 'falha ao desabilitar WMPNetworkSvc'
Disable-ServiceStartupSafe 'disable_service_xboxgipsvc' 'XboxGipSvc' 'Xbox GIP Service desabilitado (nao necessario em endpoints corporativos)' 'falha ao desabilitar XboxGipSvc'
Disable-ServiceStartupSafe 'disable_service_xblauthmanager' 'XblAuthManager' 'Xbox Live Auth Manager desabilitado' 'falha ao desabilitar XblAuthManager'
Disable-ServiceStartupSafe 'disable_service_xblgamesave' 'XblGameSave' 'Xbox Live Game Save desabilitado' 'falha ao desabilitar XblGameSave'
Disable-ServiceStartupSafe 'disable_service_xboxnetapisvc' 'XboxNetApiSvc' 'Xbox Live Networking Service desabilitado' 'falha ao desabilitar XboxNetApiSvc'

Write-RunLog 'INFO' 'firewall' 'configurando Windows Defender Firewall (3 perfis)'
Set-RegValue 'fw_domain_enable' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'EnableFirewall' 1 DWord 'firewall habilitado no perfil de dominio' 'falha ao configurar firewall de dominio'
Set-RegValue 'fw_domain_inbound' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DefaultInboundAction' 1 DWord 'perfil dominio: bloquear entrada por padrao' 'falha ao configurar inbound dominio'
Set-RegValue 'fw_domain_outbound' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' 'DefaultOutboundAction' 0 DWord 'perfil dominio: permitir saida por padrao' 'falha ao configurar outbound dominio'
Set-RegValue 'fw_private_enable' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'EnableFirewall' 1 DWord 'firewall habilitado no perfil privado' 'falha ao configurar firewall privado'
Set-RegValue 'fw_private_inbound' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DefaultInboundAction' 1 DWord 'perfil privado: bloquear entrada por padrao' 'falha ao configurar inbound privado'
Set-RegValue 'fw_private_outbound' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' 'DefaultOutboundAction' 0 DWord 'perfil privado: permitir saida por padrao' 'falha ao configurar outbound privado'
Set-RegValue 'fw_public_enable' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'EnableFirewall' 1 DWord 'firewall habilitado no perfil publico' 'falha ao configurar firewall publico'
Set-RegValue 'fw_public_inbound' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DefaultInboundAction' 1 DWord 'perfil publico: bloquear entrada por padrao' 'falha ao configurar inbound publico'
Set-RegValue 'fw_public_outbound' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DefaultOutboundAction' 0 DWord 'perfil publico: permitir saida por padrao' 'falha ao configurar outbound publico'
Set-RegValue 'fw_public_notifications' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'DisableNotifications' 1 DWord 'notificacoes do perfil publico desabilitadas' 'falha ao configurar notificacoes do perfil publico'
Set-RegValue 'fw_public_no_localpolicy' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'AllowLocalPolicyMerge' 0 DWord 'mesclagem de politica local desabilitada no perfil publico' 'falha ao configurar AllowLocalPolicyMerge'
Set-RegValue 'fw_public_no_localipsec' 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' 'AllowLocalIPsecPolicyMerge' 0 DWord 'mesclagem de politica IPsec local desabilitada no perfil publico' 'falha ao configurar AllowLocalIPsecPolicyMerge'

Write-RunLog 'INFO' 'audit_policy' 'configurando politicas de auditoria avancada via GUID'
Set-AuditPolicyGuid 'audit_credential_validation' '{0CCE923F-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Credential Validation'
Set-AuditPolicyGuid 'audit_user_account_management' '{0CCE9235-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'User Account Management'
Set-AuditPolicyGuid 'audit_plug_and_play_events' '{0CCE9248-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Plug and Play Events'
Set-AuditPolicyGuid 'audit_process_creation' '{0CCE922B-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Process Creation'
Set-AuditPolicyGuid 'audit_account_lockout' '{0CCE9217-69AE-11D9-BED3-505054503030}' 'disable' 'enable' 'Account Lockout'
Set-AuditPolicyGuid 'audit_group_membership' '{0CCE9249-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Group Membership'
Set-AuditPolicyGuid 'audit_logon' '{0CCE9215-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Logon'
Set-AuditPolicyGuid 'audit_other_logon_logoff_events' '{0CCE921C-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Other Logon/Logoff Events'
Set-AuditPolicyGuid 'audit_special_logon' '{0CCE921B-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Special Logon'
Set-AuditPolicyGuid 'audit_detailed_file_share' '{0CCE9244-69AE-11D9-BED3-505054503030}' 'disable' 'enable' 'Detailed File Share'
Set-AuditPolicyGuid 'audit_file_share' '{0CCE9224-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'File Share'
Set-AuditPolicyGuid 'audit_other_object_access_events' '{0CCE9227-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Other Object Access Events'
Set-AuditPolicyGuid 'audit_removable_storage' '{0CCE9245-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Removable Storage'
Set-AuditPolicyGuid 'audit_audit_policy_change' '{0CCE922F-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Audit Policy Change'
Set-AuditPolicyGuid 'audit_authorization_policy_change' '{0CCE9231-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Authorization Policy Change'
Set-AuditPolicyGuid 'audit_mpssvc_rule_policy_change' '{0CCE9232-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'MPSSVC Rule-Level Policy Change'
Set-AuditPolicyGuid 'audit_other_policy_change_events' '{0CCE9234-69AE-11D9-BED3-505054503030}' 'disable' 'enable' 'Other Policy Change Events'
Set-AuditPolicyGuid 'audit_sensitive_privilege_use' '{0CCE9228-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Sensitive Privilege Use'
Set-AuditPolicyGuid 'audit_ipsec_driver' '{0CCE9213-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'IPsec Driver'
Set-AuditPolicyGuid 'audit_other_system_events' '{0CCE9214-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'Other System Events'
Set-AuditPolicyGuid 'audit_security_state_change' '{0CCE9210-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Security State Change'
Set-AuditPolicyGuid 'audit_security_system_extension' '{0CCE9211-69AE-11D9-BED3-505054503030}' 'enable' 'disable' 'Security System Extension'
Set-AuditPolicyGuid 'audit_system_integrity' '{0CCE9212-69AE-11D9-BED3-505054503030}' 'enable' 'enable' 'System Integrity'

Write-RunLog 'INFO' 'additional_settings' 'iniciando parametros adicionais'
Set-RegValue 'set_enable_cert_padding_check' 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' 'EnableCertPaddingCheck' '1' String 'certificate padding check habilitado (previne exploracao de certificados mal formados)' 'falha ao configurar EnableCertPaddingCheck'
Set-RegValue 'set_sehop' 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0 DWord 'SEHOP habilitado (protecao contra overwrites de SEH)' 'falha ao configurar DisableExceptionChainValidation'
Set-RegValue 'set_disable_save_password' 'HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters' 'DisableSavePassword' 1 DWord 'salvamento de senha de acesso remoto (RAS) desabilitado' 'falha ao configurar DisableSavePassword'
Set-RegValue 'set_enable_icmp_redirect' 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'EnableICMPRedirect' 0 DWord 'redirecionamento ICMP desabilitado (previne ataques de roteamento)' 'falha ao configurar EnableICMPRedirect'
Set-RegValue 'set_keep_alive_time' 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'KeepAliveTime' 300000 DWord 'TCP KeepAliveTime configurado para 300000ms (5 min)' 'falha ao configurar KeepAliveTime'
Set-RegValue 'set_tcpmaxdataretransmissions_ipv6' 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters' 'TcpMaxDataRetransmissions' 3 DWord 'TcpMaxDataRetransmissions IPv6 configurado para 3' 'falha ao configurar TcpMaxDataRetransmissions IPv6'
Set-RegValue 'set_tcpmaxdataretransmissions_ipv4' 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'TcpMaxDataRetransmissions' 3 DWord 'TcpMaxDataRetransmissions IPv4 configurado para 3' 'falha ao configurar TcpMaxDataRetransmissions IPv4'
Set-RegValue 'set_disable_llmnr' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 DWord 'LLMNR (multicast name resolution) desabilitado (previne ataques de responder)' 'falha ao configurar EnableMulticast'
Set-RegValue 'set_minimize_connections' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' 'fMinimizeConnections' 3 DWord 'conexoes simultaneas minimizadas (modo 3: preferir rede gerenciada)' 'falha ao configurar fMinimizeConnections'
Set-RegValue 'set_auto_connect_allowed_oem' 'HKLM:\Software\Microsoft\WcmSvc\wifinetworkmanager\config' 'AutoConnectAllowedOEM' 0 DWord 'conexao automatica a hotspots (Wi-Fi Sense) desabilitada' 'falha ao configurar AutoConnectAllowedOEM'
Set-RegValue 'set_add_printer_drivers' 'HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers' 1 DWord 'instalacao de drivers de impressora restringida a administradores' 'falha ao configurar AddPrinterDrivers'
Set-RegValue 'set_redirection_guard_policy' 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers' 'RedirectionguardPolicy' 1 DWord 'Printer Redirection Guard habilitado (Win10 22H2+/Win11)' 'falha ao configurar RedirectionguardPolicy'
Set-RegValue 'set_rpc_use_named_pipe_protocol' 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcUseNamedPipeProtocol' 0 DWord 'protocolo RPC de impressora configurado (named pipe desabilitado)' 'falha ao configurar RpcUseNamedPipeProtocol'
Set-RegValue 'set_rpc_authentication' 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcAuthentication' 0 DWord 'autenticacao RPC de impressora configurada' 'falha ao configurar RpcAuthentication'
Set-RegValue 'set_rpc_protocols' 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC' 'RpcProtocols' 5 DWord 'protocolos RPC de impressora configurados para valor 5 (TCP+named pipe)' 'falha ao configurar RpcProtocols'
Set-RegValue 'disable_smb1_server' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 DWord 'SMBv1 desabilitado no servidor (previne EternalBlue e similares)' 'falha ao configurar SMB1'
Set-RegValue 'disable_smb1_client' 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4 DWord 'cliente SMBv1 (mrxsmb10) desabilitado' 'falha ao configurar mrxsmb10'
Set-RegValue 'enable_smartscreen' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1 DWord 'Windows SmartScreen habilitado para aplicativos e arquivos' 'falha ao configurar EnableSmartScreen'
Set-RegValue 'set_smartscreen_level' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Block' String 'nivel do SmartScreen configurado para Block (bloquear sem opcao de bypass)' 'falha ao configurar ShellSmartScreenLevel'

Enable-DefenderPreference 'enable_defender_realtime' { Set-MpPreference -DisableRealtimeMonitoring $false } 'protecao em tempo real do Defender habilitada' 'falha ao habilitar protecao em tempo real'
Enable-DefenderPreference 'enable_defender_behavior_monitoring' { Set-MpPreference -DisableBehaviorMonitoring $false } 'monitoramento comportamental do Defender habilitado' 'falha ao habilitar monitoramento comportamental'
Enable-DefenderPreference 'enable_defender_script_scanning' { Set-MpPreference -DisableScriptScanning $false } 'varredura de scripts do Defender habilitada' 'falha ao habilitar varredura de scripts'

if (Test-DefenderAvailable) {
    try {
        Set-MpPreference -EnableNetworkProtection Enabled
        $mp = Get-MpPreference
        if ($mp.EnableNetworkProtection -eq 1) {
            Write-RunLog 'OK' 'enable_network_protection' "Network Protection habilitada e confirmada via Get-MpPreference (build: $build)"
        } else {
            Write-RunLog 'FAIL' 'enable_network_protection' "Network Protection nao confirmou valor esperado. Valor atual: $($mp.EnableNetworkProtection)"
        }
    } catch {
        Write-RunLog 'FAIL' 'enable_network_protection' ('falha ao habilitar Network Protection | ' + $_.Exception.Message)
    }
} else {
    Write-RunLog 'SKIP' 'enable_network_protection' 'Defender nao disponivel ou gerenciado por outro produto'
}

Write-RunLog 'INFO' 'finalizando' 'gerando sumario final'

$total = $global:CountOK + $global:CountFail + $global:CountSkip
Add-Content -Path $global:RunLog -Value ''
Add-Content -Path $global:RunLog -Value '============================================================'
Add-Content -Path $global:RunLog -Value ' SUMARIO DO HARDENING BLOCKBIT WIN10/11'
Add-Content -Path $global:RunLog -Value (" Timestamp : {0}" -f $timestamp)
Add-Content -Path $global:RunLog -Value (" Host      : {0}" -f $env:COMPUTERNAME)
Add-Content -Path $global:RunLog -Value (" SO        : {0} (Build {1})" -f $caption, $build)
Add-Content -Path $global:RunLog -Value (" Dominio   : {0}" -f $domainName)
Add-Content -Path $global:RunLog -Value '============================================================'
Add-Content -Path $global:RunLog -Value (" Total de itens : {0}" -f $total)
Add-Content -Path $global:RunLog -Value (" OK             : {0}" -f $global:CountOK)
Add-Content -Path $global:RunLog -Value (" FAIL           : {0}" -f $global:CountFail)
Add-Content -Path $global:RunLog -Value (" SKIP           : {0}" -f $global:CountSkip)
if ($global:FailedItems.Count -gt 0) {
    Add-Content -Path $global:RunLog -Value '============================================================'
    Add-Content -Path $global:RunLog -Value (' ITENS COM FALHA: ' + ($global:FailedItems -join ', '))
}
if ($global:SkippedItems.Count -gt 0) {
    Add-Content -Path $global:RunLog -Value (' ITENS IGNORADOS: ' + ($global:SkippedItems -join ', '))
}
Add-Content -Path $global:RunLog -Value '============================================================'

if ($global:CountFail -eq 0) {
    Set-MarkerIfSuccess
    exit 0
} else {
    exit 1
}
