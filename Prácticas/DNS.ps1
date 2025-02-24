. "$PSScriptRoot\Funciones.ps1"

# Solicitar IP del servidor DNS
do {
    $DNSIP = Read-Host "Introduce la dirección IP del servidor DNS (IPv4)"
    if (-not (Test-IPv4 -IPAddress $DNSIP)) {
        Write-Host "La dirección IP introducida no es válida. Por favor, introduce una dirección IPv4 válida." 
    }
} until (Test-IPv4 -IPAddress $DNSIP)

# Solicitar el nombre del dominio
$DomainName = Read-Host "Introduce el nombre del dominio:"

# Verificar e instalar la característica de DNS si no está instalada
$DNSFeature = Get-WindowsFeature -Name DNS
if ($DNSFeature -and -not $DNSFeature.Installed) {
    Write-Host "Instalando la característica de DNS..." 
    Install-WindowsFeature -Name DNS -IncludeManagementTools
    Write-Host "Característica de DNS instalada." 
} else {
    Write-Host "La característica de DNS ya está instalada." 
}

# Verificar si la zona ya existe, si no, crearla
if (Get-DnsServerZone -Name $DomainName -ErrorAction SilentlyContinue) {
    Write-Host "La zona DNS '$DomainName' ya existe."
} else {
    Write-Host "Creando la zona DNS primaria para '$DomainName'..." 
    Add-DnsServerPrimaryZone -Name $DomainName -ZoneFile "$($DomainName).dns" -DynamicUpdate NonsecureAndSecure
    Write-Host "Zona DNS creada correctamente." 
}

# Agregar registros A para el dominio y "www"
Write-Host "Agregando un registro A para '$DomainName' con IP $DNSIP..." 
Add-DnsServerResourceRecordA -Name "@" -ZoneName $DomainName -IPv4Address $DNSIP
Add-DnsServerResourceRecordA -Name "www" -ZoneName $DomainName -IPv4Address $DNSIP
Write-Host "Registro A agregado exitosamente." 

# Reiniciar el servicio DNS
Write-Host "Reiniciando el servicio DNS..."
Restart-Service -Name DNS

Write-Host "El servidor DNS ha sido configurado exitosamente."
