. "$PSScriptRoot\Funciones.ps1"

# Introducción de datos
$serverIP = Get-ValidIPAddress "Introduce la dirección IP del servidor DHCP"

do {
    $startRange = Get-ValidIPAddress "Introduce la dirección IP de inicio del rango"
    $endRange = Get-ValidIPAddress "Introduce la dirección IP de fin del rango"

    if ([System.Version]$endRange -lt [System.Version]$startRange) {
        Write-Host "Error: La dirección IP de fin del rango no puede ser menor que la de inicio. Inténtalo de nuevo."
    }
} while ([System.Version]$endRange -lt [System.Version]$startRange)

$networkName = Get-ValidInput "Introduce un nombre para la red"

# Obtener detalles de red
Get-NetworkDetails -IPAddress $serverIP

# Verificar si el ámbito ya existe
if (Test-DhcpScopeExists -scopeId $serverIP) {
    Write-Host "Error: Ya existe un ámbito DHCP con la misma dirección IP del servidor ($serverIP)." 
    exit
}

# Asignar IP estática
Write-Host "Asignando la IP estática al segundo adaptador de red Ethernet0"
try {
    New-NetIPAddress -InterfaceAlias 'Ethernet1' -IPAddress $serverIP -PrefixLength 24 
    Write-Host "IP estática asignada correctamente." 
} catch {
    Write-Host "Error: No se pudo asignar la IP estática al adaptador"
}

# Instalar DHCP si no está instalado
if (-not (Get-WindowsFeature -Name DHCP | Where-Object { $_.Installed })) {
    Write-Host "Instalando el servicio de DHCP..."
    Install-WindowsFeature -Name DHCP -IncludeManagementTools
} else {
    Write-Host "El servicio de DHCP ya está instalado." 
}

# Configurar ámbito DHCP
Write-Host "Configurando el ámbito DHCP..."
try {
    Add-DhcpServerv4Scope -Name $networkName -StartRange $startRange -EndRange $endRange -SubnetMask $subnetMask -State Active -ErrorAction Stop
    Set-DhcpServerv4OptionValue -ScopeId $serverIP -OptionId 3 -Value $serverIP -ErrorAction Stop
    Write-Host "Ámbito DHCP configurado correctamente." 
} catch {
    Write-Host "Error: Ámbito ya existente o no fue posible configurarlo" 
}

# Reiniciar servicio DHCP
Write-Host "Reiniciando el servicio de DHCP..."
Restart-Service -Name DHCPServer -Force

# Verificar estado del servicio
Write-Host "Verificando el estado del servicio DHCP..."
$dhcpService = Get-Service -Name DHCPServer
if ($dhcpService.Status -eq 'Running') {
    Write-Host "El servicio de DHCP está en ejecución." 
} else {
    Write-Host "Error: El servicio de DHCP no está en ejecución."
}

# Resumen de configuración
Write-Host "Configuración del servidor DHCP completada." 
Write-Host " - Nombre de la red: $networkName"
Write-Host " - Rango de direcciones IP: $startRange - $endRange"
Write-Host " - Dirección IP del servidor DHCP: $serverIP"
