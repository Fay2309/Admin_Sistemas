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

#------------------------------------------------------------ FTP

function FTP {
    Install-WindowsFeature Web-Basic-Auth
    Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature
    Install-WindowsFeature Web-Server -IncludeAllSubFeature -IncludeManagementTools
    Import-Module WebAdministration

    if (!(Test-Path "C:\FTP")) { New-Item -Path "C:\FTP" -ItemType Directory }

    $sitio = "FTP"

    if (-not (Get-WebSite | Where-Object { $_.Name -eq $sitio })) {
        new-WebFTPSite -Name $sitio -Port '21' -PhysicalPath 'C:\FTP'
    }

    New-Item -Path "C:\FTP\LocalUser" -ItemType Directory -Force
    New-Item -Path "C:\FTP\LocalUser\Public" -ItemType Directory -Force

    Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.userIsolation.mode -Value 3

    icacls "C:\FTP" /remove "IUSR"
    icacls "C:\FTP\LocalUser" /remove "IUSR"
    icacls "C:\FTP" /remove "Todos"

    icacls "C:\FTP\LocalUser\Public" /grant "Todos:(OI)(CI)F"

    Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true
    Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true

    $paramAnon = @{
        Filter = "/system.ftpServer/security/authorization"
        Value  = @{
            accessType  = "Allow"
            users       = "*"
            permissions = 1  
        }
        PSPath   = "IIS:\"
        Location = $sitio
    }

    Add-WebConfiguration @paramAnon

    Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.security.ssl.controlChannelPolicy -Value 0
    Set-ItemProperty "IIS:\Sites\FTP" -Name ftpServer.security.ssl.dataChannelPolicy -Value 0

    Restart-Service FTPSVC
    Restart-Service W3SVC
    Restart-WebItem "IIS:\Sites\FTP" -Verbose

    Write-Host "Configuración del servidor FTP completada..."
}


function Crear-UsuarioFTP {
    $RutaLocalUser = "C:\FTP\LocalUser"
    if (-not (Test-Path $RutaLocalUser)) {
        New-Item -Path $RutaLocalUser -ItemType Directory -Force | Out-Null
        Write-Host "Se creó la carpeta 'LocalUser'." 
    }

    # Crear la carpeta Public si no existe
    $RutaPublic = "$RutaLocalUser\Public"
    if (-not (Test-Path $RutaPublic)) {
        New-Item -Path $RutaPublic -ItemType Directory -Force | Out-Null
        Write-Host "Se creó la carpeta 'Public' dentro de 'LocalUser'." 
    }

    #Solicitar el nombre del usuario
do {
    $Usuario = Read-Host "Ingrese el nombre del nuevo usuario..."
    $Usuario = $Usuario.Trim()

    if ($Usuario -match "\s") {
        Write-Host "El nombre de usuario no puede contener espacios..." 
    }
    elseif ([string]::IsNullOrEmpty($Usuario)) {
        Write-Host "El nombre de usuario no puede estar vacío..." 
    }
    elseif ($Usuario.Length -lt 4 -or $Usuario.Length -gt 20) {
        Write-Host "El nombre de usuario debe tener entre 4 y 20 caracteres..." 
    }
    elseif ($Usuario -notmatch "^[a-zA-Z_-][a-zA-Z0-9_-]*$") {
        Write-Host "El nombre de usuario solo puede contener letras, números (después del primer carácter), guiones medios y bajos..." 
    }
    elseif (Get-LocalUser -Name $Usuario -ErrorAction SilentlyContinue) {
        Write-Host "El usuario '$Usuario' ya existe..." 
    }
    else {
        break
    }
} while ($true)



    #Solicitar la contraseña
    #$SecurePassword = Read-Host -Prompt "Ingrese la contraseña" -AsSecureString
    #$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    #$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        # Validar la contraseña
    do {
        $PlainPassword = Read-Host "Ingrese la contraseña"

        if ($PlainPassword.Length -lt 8 -or $PlainPassword.Length -gt 20) {
            Write-Host "La contraseña debe tener entre 8 y 20 caracteres..." 
        }
        elseif ($PlainPassword -match "\s") {
            Write-Host "La contraseña no puede contener espacios..." 
        }
        elseif ($PlainPassword -notmatch "[A-Z]") {
            Write-Host "La contraseña debe contener al menos una letra mayúscula..." 
        }
        elseif ($PlainPassword -notmatch "[a-z]") {
            Write-Host "La contraseña debe contener al menos una letra minúscula..." 
        }
        elseif ($PlainPassword -notmatch "[0-9]") {
            Write-Host "La contraseña debe contener al menos un número..." 
        }
        elseif ($PlainPassword -notmatch "[^a-zA-Z0-9]") {
            Write-Host "La contraseña debe contener al menos un carácter especial..." 
        }
        else {
            break
        }
    } while ($true)

    # Convertir la contraseña a SecureString
    $SecurePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force

    #Crear usuario con ADSI
    $ADSI = [ADSI]"WinNT://$env:ComputerName"
    $NuevoUsuario = $ADSI.Create("User", $Usuario)
    $NuevoUsuario.SetInfo()
    $NuevoUsuario.SetPassword($PlainPassword)
    $NuevoUsuario.UserFlags = 512  
    $NuevoUsuario.SetInfo()

    Write-Host "Usuario '$Usuario' creado correctamente." 

    # Seleccionar el grupo
    do {
        Write-Host "Seleccione el grupo para el usuario:"
        Write-Host "1. Reprobados"
        Write-Host "2. Recursadores"
        $OpcionGrupo = Read-Host "Ingrese una opción (1 o 2)"

        if ($OpcionGrupo -eq "1") { $Grupo = "Reprobados" }
        elseif ($OpcionGrupo -eq "2") { $Grupo = "Recursadores" }
        else { Write-Host "Opción inválida, por favor ingrese 1 o 2."  }
    } while (-not $Grupo)

    # Asignar usuario al grupo
    $GrupoADSI = $ADSI.Children.Find($Grupo, "Group")
    $GrupoADSI.Add("WinNT://$env:ComputerName/$Usuario")
    Write-Host "Usuario '$Usuario' agregado al grupo '$Grupo'." 

    # Crear la carpeta del usuario en LocalUser
    $RutaUsuario = "$RutaLocalUser\$Usuario"
    if (-not (Test-Path $RutaUsuario)) {
        New-Item -Path $RutaUsuario -ItemType Directory -Force | Out-Null
        Write-Host "Se creó la carpeta del usuario en LocalUser." 
    }
    icacls $RutaUsuario /grant "$($Usuario):(OI)(CI)F"

    # Crear la carpeta personal dentro del usuario
    $RutaPersonal = "$RutaUsuario\$Usuario"
    if (-not (Test-Path $RutaPersonal)) {
        New-Item -Path $RutaPersonal -ItemType Directory -Force | Out-Null
        Write-Host "Se creó la carpeta personal del usuario '$Usuario'." 
    }

    # Crear enlaces simbólicos (Junctions)
    $JunctionPublic = "$RutaUsuario\Publico"
    if (-not (Test-Path $JunctionPublic)) {
        cmd /c mklink /J "$JunctionPublic" "$RutaPublic"
        Write-Host "Se creó el enlace a Public dentro de la carpeta de '$Usuario'." 
    }

    # Enlace simbólico al grupo
    $RutaGrupo = "C:\FTP\$Grupo"
    $JunctionGrupo = "$RutaUsuario\Grupo"
    if (-not (Test-Path $JunctionGrupo)) {
        cmd /c mklink /J "$JunctionGrupo" "$RutaGrupo"
        Write-Host "Se creó el enlace a la carpeta de grupo dentro de la carpeta de '$Usuario'." 
    }

    # Habilitar el usuario en el FTP
    net user $Usuario /active:yes

    Write-Host "Usuario '$Usuario' creado con éxito y configurado en FTP." 
}


function Cambiar-GrupoFTP {
    param (
        [string]$Usuario
    )

    Write-Host "Seleccione el grupo al que reasignará al usuario $Usuario"
    Write-Host "1.- Reprobados"
    Write-Host "2.- Recursadores"
    $opc = Read-Host "Elija la opción:"

    switch ($opc) {
        '1' { $nuevoGrupo = "reprobados"; $anteriorGrupo = "recursadores" }
        '2' { $nuevoGrupo = "recursadores"; $anteriorGrupo = "reprobados" }
        default { Write-Host "Opción inválida."; return }
    }

    Write-Host "Cambiando a $nuevoGrupo..."

    # Cambiar grupo del usuario
    Remove-LocalGroupMember -Group $anteriorGrupo -Member $Usuario -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group $nuevoGrupo -Member $Usuario

    # Ajustar permisos de acceso
    icacls "C:\FTP\$anteriorGrupo" /remove:g $Usuario
    icacls "C:\FTP\$nuevoGrupo" /grant "$($Usuario):(OI)(CI)F"

    # Verificar y eliminar la carpeta del grupo anterior (Grupo o grupo específico)
    $rutasEliminar = @("C:\FTP\LocalUser\$Usuario\Grupo", "C:\FTP\LocalUser\$Usuario\$anteriorGrupo")
    foreach ($ruta in $rutasEliminar) {
        if (Test-Path $ruta) {
            Remove-Item $ruta -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Crear enlace simbólico al nuevo grupo
    New-Item -ItemType Junction -Path "C:\FTP\LocalUser\$Usuario\$nuevoGrupo" -Target "C:\FTP\$nuevoGrupo"
}





function Operations {
    do {
        $Usuario = Read-Host "Ingrese el nombre del usuario sobre el que configurará (0 para cancelar)"
        if ($Usuario -eq "0") {
            Write-Host "Operación cancelada."
            return
        }
        $Usuario = $Usuario.Trim()
    } while (-not $Usuario)

    # Validar usuario con comparación exacta
    do {
        if ($Usuario -eq "0") {
            Write-Host "Operación cancelada." 
            return
        }

        $UsuarioExacto = Get-LocalUser | Where-Object { $_.Name -ceq $Usuario }

        if (-not $UsuarioExacto) {
            Write-Host "El usuario '$Usuario' no existe, ingrese uno válido o presione 0 para cancelar." 
            $Usuario = Read-Host "Ingrese el nombre del usuario sobre el que configurará (0 para cancelar)......"
        }
    } while (-not $UsuarioExacto)

    Write-Host "1.- Eliminar Usuario"
    Write-Host "2.- Cambiar grupo a usuario"
    Write-Host "3.- Volver"
    $opc = Read-Host "Elija una opción" 

    while ($opc -notmatch "^(1|2|3)$") {
        Write-Host "Opción no válida, favor de elegir una correcta." 
        $opc = Read-Host "Elija una opción" 
    }

    if ($opc -eq "1") {
        Eliminar-UsuarioFTP -Usuario $Usuario
    }
    elseif ($opc -eq "2") {
        Cambiar-GrupoFTP -Usuario $Usuario
    }
    elseif ($opc -eq "3") {
        return
    }
}

function Eliminar-UsuarioFTP {
    param (
        [string]$Usuario
    )

    # Ruta de la carpeta del usuario
    $RutaUsuario = "C:\FTP\LocalUser\$Usuario"

    # Verificar si la carpeta del usuario existe y eliminarla
    if (Test-Path $RutaUsuario) {
        try {
            # Buscar y eliminar enlaces simbólicos (Junctions) dentro de la carpeta
            Get-ChildItem -Path $RutaUsuario | ForEach-Object {
                if ($_.Attributes -match "ReparsePoint") {
                    cmd.exe /c rmdir $_.FullName
                    Write-Host "Enlace simbólico eliminado: $($_.FullName)" 
                }
            }

            # Ahora eliminar la carpeta completa del usuario
            Remove-Item -Path $RutaUsuario -Recurse -Force
            Write-Host "Carpeta del usuario '$Usuario' eliminada correctamente." 
        }
        catch {
            Write-Host "No se pudo eliminar la carpeta del usuario '$Usuario'. Verifique permisos." 
            return
        }
    }
    else {
        Write-Host "No se encontró la carpeta del usuario '$Usuario'." 
    }

    # Eliminar al usuario de cualquier grupo si aplica
    $Grupos = @("Reprobados", "Recursadores")
    foreach ($Grupo in $Grupos) {
        $GrupoADSI = [ADSI]"WinNT://$env:ComputerName/$Grupo,group"
        if ($GrupoADSI.Members() | Where-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) -ceq $Usuario }) {
            $GrupoADSI.Remove("WinNT://$env:ComputerName/$Usuario")
            Write-Host "Usuario '$Usuario' eliminado del grupo '$Grupo'." 
        }
    }

    # Eliminar al usuario del sistema
    try {
        Remove-LocalUser -Name $Usuario -ErrorAction Stop
        Write-Host "Usuario '$Usuario' eliminado del sistema." 
    }
    catch {
        Write-Host "Error al eliminar el usuario '$Usuario'. Verifique permisos." 
        return
    }

    Write-Host "Eliminación del usuario '$Usuario' completada." 
}

