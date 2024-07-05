param (
    [switch]$GetSystemInfo,
    [switch]$CheckWindowsDefender,
    [switch]$CheckFirewallRules,
    [switch]$CheckSystemUpdates,
    [switch]$CheckAdminPassword,
    [switch]$CheckBitLocker,
    [switch]$CheckOpenPorts,
    [switch]$CheckUSBProtection,
    [switch]$CheckPendingUpdates,
    [switch]$CheckDNSCache,
    [switch]$CheckUserActivities,
    [switch]$MonitorLogs,
    [switch]$AuditUserAccounts,
    [switch]$CheckFileIntegrity,
    [switch]$CheckVPNProxies,
    [switch]$MonitorAnonConnections
)

Set-ExecutionPolicy RemoteSigned -Scope Process


# Inicializar o relatório como um hashtable
$report = @{
    "System Information" = @()
    "Windows Defender"= @()
    "Specific firewall rules are enforced" = @()
    "Open TCP Ports" = @()
    "USB Malware Protection" = ""
    "Pending Updates" = @()
    "DNS Cache Check" = @()
    "User Activities" = @()
    "System Logs" = @()
    "Application Logs" = @()
    "User Account Audit" = @()
    "File Integrity Check" = @()
    "VPN and Proxy Check" = @()
    "Anonymous Connections" = @()
}

# Obter informações do sistema operacional
$SystemInfo = @()
if ($GetSystemInfo) {
    $osInfo = Get-ComputerInfo -Property "OsName", "OsArchitecture", "WindowsVersion", "WindowsBuildLabEx"
    $SystemInfo = @{
        "Operating System" = $osInfo.OsName
        "Architecture" = $osInfo.OsArchitecture
        "Windows Version" = $osInfo.WindowsVersion
    }
}

# Verificar se o Windows Defender está ativo
$windowsDefender = @()
if ($CheckWindowsDefender) {
    # Verifica se o Windows Defender está ativado
    $defenderStatus = Get-MpComputerStatus

    if ($defenderStatus.AntivirusEnabled -eq $true) {
        $windowsDefender = @{
            "Window defender Status" = "Ative"
        }
    } else {
        $windowsDefender = @{
            "Window defender Status" = "Inactive"
        }
    }
    $SystemInfo += $windowsDefender
}


# Verificar se o BitLocker está habilitado
if ($CheckBitLocker) {
    try {
        $bitlockerStatus = Get-BitLockerVolume -MountPoint C:
        if ($bitlockerStatus.VolumeStatus -eq "FullyEncrypted") {
            $SystemInfo += @{ "BitLocker Status" = "Enabled."}
        } else {
            $SystemInfo += @{ "BitLocker Status" = "Disabled."}
        }
    } catch {
        $SystemInfo += @{ "BitLocker Status" = "Error checking."}
    }
}

# Verificar se o sistema está atualizado
if ($CheckSystemUpdates) {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
    }
    Import-Module PSWindowsUpdate

    $updates = Get-WUList | Where-Object {$_.IsInstalled -eq $false}
    if ($updates.Count -eq 0) {
        $SystemInfo += @{"System Update Status" = "Updated."}
    } else {
        $SystemInfo += @{"System Update Status" = "Not updated"}
        $updates | ForEach-Object {
            $update = @{
                "Title" = $_.Title
                "Description" = $_.Description
                "Release Date" = if ($_.ReleaseDate) { $_.ReleaseDate } else { "Unknown" }
            }
            $report["Pending Updates"] += $update
        }
    }
}
$report["System Information"] = $SystemInfo


# Mapeamento dos valores para os perfis de firewall
function Get-FirewallProfileText($profiles) {
    switch ($profiles) {
        1 { return "Domain" }
        2 { return "Private" }
        4 { return "Public" }
        default { return "Unknown" }
    }
}

# Mapeamento dos valores para a direção do firewall
function Get-FirewallDirectionText($direction) {
    switch ($direction) {
        1 { return "Inbound" }
        2 { return "Outbound" }
        default { return "Unknown" }
    }
}

# Mapeamento dos valores para a ação do firewall
function Get-FirewallActionText($action) {
    switch ($action) {
        1 { return "Allow" }
        2 { return "Block" }
        3 { return "Log" }
        4 { return "Bypass" }
        default { return "Unknown" }
    }
}

# Verificar se regras específicas de firewall estão aplicadas
if ($CheckFirewallRules) {
    $firewallRules = Get-NetFirewallRule -Direction Inbound -Action Block
    if ($firewallRules.Count -gt 0) {
        $firewallRules | ForEach-Object { 
            $rule = @{
                "Name" = $_.DisplayName
                "Action" = Get-FirewallActionText([int]$_.Action)
                "Profile" = Get-FirewallProfileText([int]$_.Profile)
                "Direction" = Get-FirewallDirectionText([int]$_.Direction)
                "Description" = $_.Description
            }
            $report["Specific firewall rules are enforced"] += $rule
        }  
    }
}

# Definir as portas a serem verificadas
$portsToCheck = 21,22,23,25,53,69,80,443,8080,8443,135,137,138,139

# Obter conexões TCP
if ($CheckOpenPorts) {
    $tcpConnections = Get-NetTCPConnection

    # Mapear os valores numéricos dos estados para mensagens de texto
    function Get-TCPStateText($state) {
        switch ($state) {
            "1" { return "CLOSED" }
            "2" { return "LISTEN" }
            "3" { return "SYN-SENT" }
            "4" { return "SYN-RECEIVED" }
            "5" { return "ESTABLISHED" }
            "6" { return "FIN-WAIT-1" }
            "7" { return "FIN-WAIT-2" }
            "8" { return "CLOSE-WAIT" }
            "9" { return "CLOSING" }
            "10" { return "LAST-ACK" }
            "11" { return "TIME-WAIT" }
            "12" { return "DELETE TCB" }
            default { return "UNKNOWN" }
        }
    }

    # Verificar portas abertas
    $openPorts = @()
    foreach ($conn in $tcpConnections) {
        if ($portsToCheck -contains $conn.LocalPort) {
            $stateText = Get-TCPStateText([int]$conn.State)
            $openPorts += @{
                "Local Address" = $conn.LocalAddress
                "Local Port" = $conn.LocalPort
                "Remote Address" = $conn.RemoteAddress
                "Remote Port" = $conn.RemotePort
                "State" = $stateText
            }
        }
    }
    $report["Open TCP Ports"] = $openPorts
}

# Função para verificar a proteção contra malware via USB
function Check-USBMalwareProtection {
    $usbProtection = @{}

    # Verificar status da execução automática
    $autoRunKey = 'HKLM:\SOFTWARE\Computer\HKEY_CURRENT_USER\Software\Policies'
    $autoRunProperty = 'NoDriveTypeAutoRun'
    if (Test-Path -Path $autoRunKey) {
        $autoRunSettings = Get-ItemProperty -Path $autoRunKey -Name $autoRunProperty -ErrorAction SilentlyContinue
        if ($null -ne $autoRunSettings -and $autoRunSettings.$autoRunProperty -eq 255) {
            $usbProtection["AutoRun Status"] = "AutoRun is disabled."
        } else {
            $usbProtection["AutoRun Status"] = "AutoRun is enabled. This can be a security risk."
        }
    } else {
        $usbProtection["AutoRun Status"] = "AutoRun is enabled. This can be a security risk."
    }

    # Verificar políticas de armazenamento removível
    $storagePolicyKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\UsbStor'
    $storagePolicyProperty = 'Start'
    if (Test-Path -Path $storagePolicyKey) {
        $storagePolicy = Get-ItemProperty -Path $storagePolicyKey -Name $storagePolicyProperty -ErrorAction SilentlyContinue
        if ($null -ne $storagePolicy -and $storagePolicy.$storagePolicyProperty -eq 4) {
            $usbProtection["USB Storage Policy"] = "USB storage devices are disabled."
        } else {
            $usbProtection["USB Storage Policy"] = "USB storage devices are enabled. This can be a security risk."
        }
    } else {
        $usbProtection["USB Storage Policy"] = "USB storage devices are enabled. This can be a security risk."
    }

    return $usbProtection
}

# Adicionar a proteção contra malware via USB ao relatório
if ($CheckUSBProtection) {
    $report["USB Malware Protection"] = Check-USBMalwareProtection
}

# Função para verificar histórico de navegação contra uma lista de IPs/domínios maliciosos
function Check-DNSCache {
    param (
        [string]$MaliciousDomainsPath = "urls_wordlist.txt"
    )
    try {
        # Verifica se o arquivo de domínios maliciosos existe
        if (-Not (Test-Path -Path $MaliciousDomainsPath)) {
            Write-Error "Malicious domains file not found at path: $MaliciousDomainsPath"
            return @()
        }
        
        # Carrega os domínios maliciosos do ficheiro
        $maliciousDomains = Get-Content -Path $MaliciousDomainsPath
        # Converte a lista de domínios maliciosos para um hash set para busca rápida
        $maliciousDomainsSet = [HashSet[string]]::new($maliciousDomains)

        # Inicializa a lista para armazenar URLs maliciosos
        $maliciousUrls = @()

        # Função auxiliar para verificar URLs maliciosos em um histórico de navegação
        function Check-History ($history) {
            foreach ($entry in $history) {
                $url = $entry.url
                $domain = ([uri]$url).Host
                if ($maliciousDomains.Contains($domain)) {
                    $maliciousUrls += $url
                }
            }
        }

        # Verifica histórico do Internet Explorer
        $webHistoryEvents = Get-WinEvent -LogName "Microsoft-Windows-IE/Operational" | Where-Object { $_.Id -eq 1037 }
        foreach ($event in $webHistoryEvents) {
            $url = $event.Properties[1].Value
            $domain = ([uri]$url).Host
            if ($maliciousDomainsSet.Contains($domain)) {
                $maliciousUrls += $url
            }
        }

        # Verifica histórico do Google Chrome
        $chromeHistoryPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
        if (Test-Path $chromeHistoryPath) {
            $chromeHistory = Import-Csv -Path $chromeHistoryPath -Delimiter "`t" | Where-Object { $_.url }
            Check-History $chromeHistory
        }

        # Verifica histórico do Mozilla Firefox
        $firefoxHistoryPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*\places.sqlite"
        $firefoxHistoryFiles = Get-ChildItem -Path $firefoxHistoryPath
        foreach ($file in $firefoxHistoryFiles) {
            $firefoxHistory = sqlite3 $file.FullName "SELECT url FROM moz_places" | ConvertFrom-Csv -Delimiter "`t"
            Check-History $firefoxHistory
        }

        # Verifica histórico do Microsoft Edge
        $edgeHistoryPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        if (Test-Path $edgeHistoryPath) {
            $edgeHistory = Import-Csv -Path $edgeHistoryPath -Delimiter "`t" | Where-Object { $_.url }
            Check-History $edgeHistory
        }

        return $maliciousUrls
    }
    catch {
        Write-Error "An error occurred: $_"
        return @()
    }
}

# Verificar a cache DNS e adicionar ao relatório se necessário
if ($CheckDNSCache) {
    $maliciousDnsCache = Check-DNSCache
    if ($maliciousDnsCache.Count -gt 0) {
        $report["DNS Cache Check"] = $maliciousDnsCache
    } else {
        $report["DNS Cache Check"] = "No malicious URLs found in DNS cache."
    }
}



# Função para monitorar logs do sistema
function Monitor-SystemLogs {
    $systemLogs = @()
    $events = Get-WinEvent -LogName "System" -MaxEvents 10
    foreach ($event in $events) {
        $systemLogs += @{
            "TimeCreated" = $event.TimeCreated
            "Message" = $event.Message
            "LevelDisplayName" = $event.LevelDisplayName
        }
    }
    return $systemLogs
}

# Função para monitorar logs de aplicativos
function Monitor-ApplicationLogs {
    $applicationLogs = @()
    $events = Get-WinEvent -LogName "Application" -MaxEvents 10
    foreach ($event in $events) {
        $applicationLogs += @{
            "TimeCreated" = $event.TimeCreated
            "Message" = $event.Message
            "LevelDisplayName" = $event.LevelDisplayName
        }
    }
    return $applicationLogs
}

# Adicionar monitoramento de logs ao relatório
if ($MonitorLogs) {
    $report["System Logs"] = Monitor-SystemLogs
    $report["Application Logs"] = Monitor-ApplicationLogs
}

# Função para auditoria de contas de usuário e grupos
function Audit-UserAccounts {
    $userAccountAudit = @()
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($user in $users) {
        $userAccountAudit += @{
            "Name" = $user.Name
            "FullName" = $user.FullName
            "LastLogon" = $user.LastLogon
        }
    }
    return $userAccountAudit
}

# Adicionar auditoria de contas de usuário ao relatório
if ($AuditUserAccounts) {
    $report["User Account Audit"] = Audit-UserAccounts
}

# Função para verificar a integridade de arquivos críticos
function Check-FileIntegrity {
    param (
        [string]$filesListPath = "files_check.txt"
    )

    # Verifica se o arquivo de lista existe
    if (-Not (Test-Path -Path $filesListPath)) {
        Write-Error "File list not found: $filesListPath"
        return
    }

    # Lê os arquivos a serem verificados a partir do arquivo de texto
    $filesToCheck = Get-Content -Path $filesListPath

    # Inicializa uma lista vazia para armazenar os resultados da verificação de integridade
    $fileIntegrity = @()

    # Itera sobre cada arquivo na lista
    foreach ($file in $filesToCheck) {
        # Verifica se o arquivo existe
        if (Test-Path -Path $file) {
            # Calcula o hash SHA256 do arquivo
            $fileHash = Get-FileHash -Path $file -Algorithm SHA256
            
            # Adiciona um item à lista de resultados com o caminho do arquivo e o hash calculado
            $fileIntegrity += @{
                "File" = $file
                "Hash" = $fileHash.Hash
                "LastModified" = (Get-Item -Path $file).LastWriteTime
                "CheckedAt" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
        } else {
            # Adiciona um item à lista de resultados com o caminho do arquivo e uma mensagem de arquivo não encontrado
            $fileIntegrity += @{
                "File" = $file
                "Hash" = "File not found"
                "LastModified" = "N/A"
                "CheckedAt" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
    }

    # Retorna a lista de resultados
    return $fileIntegrity
}

# Adicionar verificação de integridade de arquivos ao relatório
if ($CheckFileIntegrity) {
    $report["File Integrity Check"] = Check-FileIntegrity
}

# Função para verificar conexões VPN e proxies
function Check-VPNProxies {
    $vpnProxies = @()
    $connections = Get-VpnConnection
    foreach ($conn in $connections) {
        $vpnProxies += @{
            "Name" = $conn.Name
            "ServerAddress" = $conn.ServerAddress
            "ConnectionStatus" = $conn.ConnectionStatus
        }
    }
    return $vpnProxies
}

# Adicionar verificação de conexões VPN e proxies ao relatório
if ($CheckVPNProxies) {
    $report["VPN and Proxy Check"] = Check-VPNProxies
}

# Função para monitorar conexões de rede anônimas
function Monitor-AnonConnections {
    $anonConnections = @()
    $connections = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -match "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" }
    foreach ($conn in $connections) {
        $anonConnections += @{
            "LocalAddress" = $conn.LocalAddress
            "LocalPort" = $conn.LocalPort
            "RemoteAddress" = $conn.RemoteAddress
            "RemotePort" = $conn.RemotePort
        }
    }
    return $anonConnections
}

# Adicionar monitoramento de conexões anônimas ao relatório
if ($MonitorAnonConnections) {
    $report["Anonymous Connections"] = Monitor-AnonConnections
}

# Converter o relatório para JSON e exportar, sobrescrevendo o arquivo existente se houver
$report | ConvertTo-Json -Depth 4 | Out-File -FilePath "security_report.json" -Encoding UTF8 -Force

Write-Host "Security report exported to 'security_report.json'."
