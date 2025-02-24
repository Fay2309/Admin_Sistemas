function Test-IPv4 {
    param ([string]$IPAddress)
    $IPv4Regex = '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return $IPAddress -match $IPv4Regex
}

function Get-ValidIPAddress {
    param (
        [string]$message
    )
    do {
        $ip = Read-Host $message
        if ([string]::IsNullOrWhiteSpace($ip)) {
            Write-Host "Error: El campo no puede estar vacío. Inténtalo de nuevo."
        } elseif (-not (Validate-IPAddress $ip)) {
            Write-Host "Error: La dirección IP no es válida. Inténtalo de nuevo."
        }
    } while ([string]::IsNullOrWhiteSpace($ip) -or (-not (Validate-IPAddress $ip)))
    return $ip
}

function Get-ValidInput {
    param (
        [string]$message
    )
    do {
        $input = Read-Host $message
        if ([string]::IsNullOrWhiteSpace($input)) {
            Write-Host "Error: El campo no puede estar vacío. Inténtalo de nuevo." 
        }
    } while ([string]::IsNullOrWhiteSpace($input))
    return $input
}

function Test-DhcpScopeExists {
    param (
        [string]$scopeId
    )
    $existingScopes = Get-DhcpServerv4Scope -ErrorAction SilentlyContinue
    return $existingScopes | Where-Object { $_.ScopeId -eq $scopeId }
}

function Get-NetworkDetails {
    param (
        [string]$IPAddress,
        [int]$CIDR = 24
    )

    if ($IPAddress -notmatch "^\d{1,3}(\.\d{1,3}){3}$") {
        Write-Host "Error: IP inválida. Introduce una IP válida." -ForegroundColor Red
        return
    }

    $subnetMasks = @{
        8  = "255.0.0.0"; 9  = "255.128.0.0"; 10 = "255.192.0.0"; 11 = "255.224.0.0"; 12 = "255.240.0.0"
        13 = "255.248.0.0"; 14 = "255.252.0.0"; 15 = "255.254.0.0"; 16 = "255.255.0.0"; 17 = "255.255.128.0"
        18 = "255.255.192.0"; 19 = "255.255.224.0"; 20 = "255.255.240.0"; 21 = "255.255.248.0"; 22 = "255.255.252.0"
        23 = "255.255.254.0"; 24 = "255.255.255.0"; 25 = "255.255.255.128"; 26 = "255.255.255.192"; 27 = "255.255.255.224"
        28 = "255.255.255.240"; 29 = "255.255.255.248"; 30 = "255.255.255.252"; 31 = "255.255.255.254"; 32 = "255.255.255.255"
    }

    if (-not $subnetMasks.ContainsKey($CIDR)) {
        Write-Host "Error: Prefijo CIDR inválido. Debe estar entre 8 y 32." 
        return
    }
    $subnetMask = $subnetMasks[$CIDR]

    $octets = $IPAddress -split "\."
    $networkAddress = "$($octets[0]).$($octets[1]).$($octets[2]).0"

    $global:SubnetMask = $subnetMask
    $global:NetworkIP = $networkAddress
}

#-------------------------------------------------------------------------------- SSH

Function Add_User{

    param (
        [string]$usuario,
        [string]$nombreCompleto,
        [string]$descripcion
    )

    
    while (-not $usuario) {
        $usuario = Read-Host "Ingrese el nombre de usuario..."
    }

    #manejo de contraseñas, se usa AsSecureString para encriptarla, luego, para verificar que si tiene algo se pasa a plano
    $SecurePassword = Get-ValidPassword

    while (-not $nombreCompleto) {
        $nombreCompleto = Read-Host "Ingrese el nombre completo..."
    }

    while (-not $descripcion) {
        $descripcion = Read-Host "Ingrese una descripción..."
    }

    New-LocalUser -Name $usuario -Password $SecurePassword -FullName $nombreCompleto -Description $descripcion


        Write-Host "`nElija a qué grupo será asignado el usuario..."
        Write-Host "1.- Administradores"
        Write-Host "2.- Usuarios de escritorio remoto"
    
        $group = Read-Host 

        while ($group -notmatch "^(1|2)$") {
            Write-Host "Opción no válida, por favor elija 1 o 2."
            $group = Read-Host "`nSeleccione un grupo"
        }

        if ($group -eq "1") {
            Add-LocalGroupMember -Group "Administradores" -Member $usuario
            Write-Host "Usuario agregado al grupo Administradores.`n" 
        } elseif ($group -eq "2") {
            Add-LocalGroupMember -Group "Usuarios de Escritorio Remoto" -Member $usuario
            Write-Host "Usuario agregado al grupo Usuarios de Escritorio Remoto.`n"
        }

}



#manejo de contraseñas, se usa AsSecureString para encriptarla, luego, para verificar que si tiene algo se pasa a plano
#Se maneja que la contraseña sea valida según la seguridad de Windows
function Get-ValidPassword {
    while ($true) {
        $SecurePassword = Read-Host -Prompt "Ingrese la contraseña" -AsSecureString

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        if ($PlainPassword.Length -lt 8) {
            Write-Host "La contraseña debe tener al menos 8 caracteres. Inténtelo de nuevo." 
            continue
        }

        if (-not ($PlainPassword -match "[A-Z]") -or
            -not ($PlainPassword -match "[a-z]") -or
            -not ($PlainPassword -match "[0-9]") -or
            -not ($PlainPassword -match "[!@#$%^&*()_+{}|:<>?]")) {
            Write-Host "La contraseña debe incluir mayúsculas, minúsculas, números y caracteres especiales. Inténtelo de nuevo." 
            continue
        }

        return $SecurePassword
    }
}

function Delete_User{
    
    while (-not $usuario_borrado) {
        $usuario_borrado = Read-Host "`nIngrese el nombre del usuario que desea eliminar"
    }

    $usuario_existe = Get-LocalUser -Name $usuario_borrado -ErrorAction SilentlyContinue

    while (-not $usuario_existe) {
        Write-Host "`nEl usuario '$usuario_borrado' no existe. Por favor ingrese un usuario válido..."
        $usuario_borrado = Read-Host "`nIngrese el nombre del usuario que desea eliminar"
        $usuario_existe = Get-LocalUser -Name $usuario_borrado -ErrorAction SilentlyContinue
    }

    Remove-LocalUser -Name $usuario_borrado

    Write-Host "`nUsuario eliminado con exito...`n"
}

function Info_User {
    while (-not $info_user) {
        $info_user = Read-Host "`nIngrese el usuario del que desea obtener información..."
    }

    $usuario_existe = Get-LocalUser -Name $info_user -ErrorAction SilentlyContinue

    while (-not $usuario_existe) {
        Write-Host "`nEl usuario '$info_user' no existe. Por favor ingrese un usuario válido..."
        $info_user = Read-Host "`nIngrese el usuario del que desea obtener información..."
        $usuario_existe = Get-LocalUser -Name $info_user -ErrorAction SilentlyContinue
    }

    net user $info_user

}
