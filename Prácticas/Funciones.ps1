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

#---------------------------------------------------------------------------------------- HTTP

function Get-ValidPort {
    $reservedPorts = @(21, 22, 23, 25, 53, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 1723, 3306, 3389, 5900)

    do {
        $port = Read-Host "Ingrese el puerto"

        # Validar que el puerto sea un número
        if ($port -match "^\d+$") {
            $port = [int]$port

            if ($port -eq 0 -or $port -gt 65535) {
                Write-Host "El puerto debe ser un número entre 1 y 65535. Intente con otro."
                continue
            }

            # Verificar si está en la lista de reservados
            if ($reservedPorts -contains $port) {
                Write-Host "El puerto $port está reservado para otro servicio. Intente con otro."
                continue
            }

            # Verificar si el puerto está en uso
            $inUse = Test-NetConnection -Port $port -ComputerName "localhost" | Select-Object -ExpandProperty TcpTestSucceeded
            
            if (-not $inUse) {
                return $port
            } else {
                Write-Host "El puerto $port ya está en uso. Intente con otro."
            }
        } else {
            Write-Host "Puerto inválido."
        }
    } while ($true)
}


# Función para obtener la versión de Tomcat elegida por el usuario
function Get-TomcatVersion {
    do {
        Write-Host "Seleccione la versión de Tomcat a instalar:"
        Write-Host "1 - LTS"
        Write-Host "2 - Desarrollo"
        $selection = Read-Host "Ingrese su opción (1 o 2)"
        
        if ($selection -eq "1") {
            return "10.1.39"
        } elseif ($selection -eq "2") {
            return "11.0.5"
        } else {
            Write-Host "Opción inválida. Intente de nuevo."
        }
    } while ($true)
}


# Función para instalar Tomcat
function Install-Tomcat {
    param (
        [string]$tomcatVersion,
        [int]$port
    )
    
    # Definir la URL de descarga según la versión seleccionada
    if ($tomcatVersion -like "10.*") {
        $downloadUrl = "https://dlcdn.apache.org/tomcat/tomcat-10/v$tomcatVersion/bin/apache-tomcat-$tomcatVersion-windows-x64.zip"
    } elseif ($tomcatVersion -like "11.*") {
        $downloadUrl = "https://dlcdn.apache.org/tomcat/tomcat-11/v$tomcatVersion/bin/apache-tomcat-$tomcatVersion-windows-x64.zip"
    } else {
        Write-Host "Error: Versión de Tomcat no válida."
        return
    }
    
    # Definir rutas de instalación y archivos
    $installPath = "C:\Tomcat\apache-tomcat-$tomcatVersion"
    $zipFile = "C:\Temp\apache-tomcat-$tomcatVersion.zip"
    $serviceName = "Tomcat$($tomcatVersion.Split('.')[0])"  # Tomcat10 o Tomcat11

    # Verificar si el servicio ya existe
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "El servicio $serviceName ya existe. Volviendo al menú..."
        return
    }
    
    # Crear carpeta temporal si no existe
    if (!(Test-Path "C:\Temp")) { 
        New-Item -Path "C:\Temp" -ItemType Directory | Out-Null 
    }
    
    # Descargar Tomcat
    Write-Host "Descargando Tomcat $tomcatVersion desde $downloadUrl..."
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile
    
    if (!(Test-Path $zipFile)) {
        Write-Host "Error: No se pudo descargar el archivo ZIP."
        return
    }
    
    # Extraer archivos
    Write-Host "Extrayendo archivos..."
    Expand-Archive -Path $zipFile -DestinationPath "C:\Tomcat" -Force
    
    # Verificar que server.xml exista
    if (!(Test-Path "$installPath\conf\server.xml")) {
        Write-Host "Error: El archivo server.xml no se encontró en la ruta esperada."
        return
    }
    
    # Configurar el puerto en server.xml
    $serverXmlPath = "$installPath\conf\server.xml"
    (Get-Content $serverXmlPath) -replace 'port="8080"', "port=`"$port`"" | Set-Content $serverXmlPath
    
    # Instalar el servicio usando service.bat
    Write-Host "Instalando el servicio $serviceName..."
    cd "$installPath\bin"
    .\service.bat install $serviceName
    
    # Verificar que el servicio se haya creado correctamente
    if (!(Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Write-Host "Error: No se pudo crear el servicio $serviceName."
        return
    }
    
    # Iniciar el servicio
    Write-Host "Iniciando servicio $serviceName..."
    Start-Service -Name $serviceName
    Write-Host "Tomcat $tomcatVersion ha sido instalado y configurado en el puerto $port."
}


function Install-Nginx {
    param (
        [string]$nginxDescargas = "https://nginx.org/en/download.html"
    )

    # Obtener la página de descargas de Nginx
    $paginaNginx = (Invoke-WebRequest -Uri $nginxDescargas -UseBasicParsing).Content

    # Expresión regular para encontrar versiones de Nginx
    $versionRegex = 'nginx-(\d+\.\d+\.\d+)\.zip'

    # Encontrar todas las versiones en la página
    $versiones = [regex]::Matches($paginaNginx, $versionRegex) | ForEach-Object { $_.Groups[1].Value }

    # Asignar versiones LTS y de desarrollo
    $versionLTSNginx = $versiones[6]  
    $versionDevNginx = $versiones[0]  

    # Menú de selección de versión
    echo "Instalador de Nginx"
    echo "1. Versión LTS $versionLTSNginx"
    echo "2. Versión de desarrollo $versionDevNginx"
    echo "3. Salir"
    $opcNginx = Read-Host "Selecciona una versión"

    switch ($opcNginx) {
        "1" {
            $port = Get-ValidPort
            Install-NginxVersion -version $versionLTSNginx -port $port
        }
        "2" {
            $port = Get-ValidPort
            Install-NginxVersion -version $versionDevNginx -port $port
        }
        "3" {
           return
        }
        default {
            echo "Seleccione una opción válida..."
        }
    }
}

function Install-NginxVersion {
    param (
        [string]$version,
        [int]$port
    )

    try {
        # Detener cualquier instancia de Nginx en ejecución
        Stop-Process -Name nginx -ErrorAction SilentlyContinue

        # Crear carpeta C:\nginx si no existe
        if (-not (Test-Path "C:\nginx")) {
            New-Item -ItemType Directory -Path "C:\nginx"
        }

        # Descargar la versión seleccionada de Nginx
        echo "Instalando versión $version"
        $downloadUrl = "https://nginx.org/download/nginx-$version.zip"
        $zipFile = "C:\nginx\nginx-$version.zip"
            if ($downloadMethod -eq "1") {
        # Descargar desde la web oficial
        if ($tomcatVersion -like "10.*") {
            $downloadUrl = "https://dlcdn.apache.org/tomcat/tomcat-10/v$tomcatVersion/bin/apache-tomcat-$tomcatVersion-windows-x64.zip"
        } elseif ($tomcatVersion -like "11.*") {
            $downloadUrl = "https://dlcdn.apache.org/tomcat/tomcat-11/v$tomcatVersion/bin/apache-tomcat-$tomcatVersion-windows-x64.zip"
        } else {
            Write-Host "Error: Versión de Tomcat no válida."
            return
        }

        Write-Host "Descargando Tomcat $tomcatVersion desde la web oficial..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile
    } elseif ($downloadMethod -eq "2") {
        # Descargar desde el servidor FTP
        Write-Host "Hola profe"
    } else {
        Write-Host "Opción no válida. Saliendo..."
        return
    }

        # Extraer el archivo ZIP
        Expand-Archive -Path $zipFile -DestinationPath "C:\nginx" -Force

        # Cambiar al directorio de Nginx
        $nginxDir = "C:\nginx\nginx-$version"
        cd $nginxDir

        # Configurar el puerto en nginx.conf
        $nginxConfigPath = "$nginxDir\conf\nginx.conf"
        (Get-Content $nginxConfigPath) -replace "listen\s+[0-9]{1,5}", "listen       $port" | Set-Content $nginxConfigPath

        # Verificar el cambio en nginx.conf
        Select-String -Path $nginxConfigPath -Pattern "listen\s+[0-9]{1,5}"

        # Iniciar Nginx
        Start-Process "$nginxDir\nginx.exe"

        # Verificar que Nginx esté en ejecución
        Get-Process | Where-Object { $_.ProcessName -like "*nginx*" }

        echo "Se instaló la versión $version de Nginx en C:\nginx y está corriendo en el puerto $port"
    }
    catch {
        echo "Error: $($Error[0].ToString())"
    }
}

function Install-IIS {
    # Verificar si IIS está instalado
    $iisFeature = Get-WindowsFeature -Name Web-Server
    if ($iisFeature.Installed -eq $false) {
        Write-Host "IIS no está instalado. Instalando..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools -NoProgress
    } else {
        Write-Host "IIS ya está instalado."
    }

    # Obtener un puerto válido
    $port = Get-ValidPort

    # Validar que el puerto sea válido antes de continuar
    if ($port -lt 1 -or $port -gt 65535) {
        Write-Host "Error: El puerto $port no es válido. Debe estar entre 1 y 65535."
        return
    }

    # Iniciar el servicio IIS si no está corriendo
    if ((Get-Service -Name W3SVC).Status -ne "Running") {
        Write-Host "Iniciando el servicio IIS..."
        Start-Service -Name W3SVC
    }

    # Importar módulo de administración web
    Import-Module WebAdministration

    # Verificar si el sitio predeterminado existe
    $defaultSite = Get-WebSite -Name "Default Web Site" -ErrorAction SilentlyContinue
    if ($defaultSite) {
        Write-Host "El sitio 'Default Web Site' ya existe. Configurando..."
        Stop-WebSite -Name "Default Web Site"

        # Verificar si hay un binding en el puerto 80 antes de eliminarlo
        $binding80 = Get-WebBinding -Name "Default Web Site" | Where-Object { $_.bindingInformation -eq "*:80:" }
        if ($binding80) {
            Remove-WebBinding -Name "Default Web Site" -BindingInformation "*:80:"
        }

        # Verificar si el binding en el nuevo puerto ya existe antes de agregarlo
        $existingBinding = Get-WebBinding -Name "Default Web Site" | Where-Object { $_.bindingInformation -match "\*:$($port):" }
        if (-not $existingBinding) {
            New-WebBinding -Name "Default Web Site" -Protocol http -Port $port
        } else {
            Write-Host "El sitio ya tiene un binding en el puerto $port."
        }

        Start-WebSite -Name "Default Web Site"
    } else {
        Write-Host "No se encontró 'Default Web Site'. Creándolo..."
        New-WebSite -Name "Default Web Site" -Port $port -PhysicalPath "C:\inetpub\wwwroot"
    }

    # Verificar si el puerto está escuchando
    Write-Host "Verificando si el puerto $port está escuchando..."
    try {
        $portListening = Test-NetConnection -ComputerName localhost -Port $port -ErrorAction Stop
        if ($portListening.TcpTestSucceeded) {
            Write-Host "IIS está corriendo correctamente en http://localhost:$port"
        } else {
            Write-Host "Error: El puerto $port no está escuchando. Revisa la configuración de IIS."
        }
    } catch {
        Write-Host "Error: No se pudo verificar el puerto $port. Asegúrate de que sea un puerto válido."
    }
}

#------------------------------------------------------------- SSL

# Función para instalar Tomcat con SSL
function Install-Tomcatssl {
    param (
        [string]$tomcatVersion,
        [int]$port
    )

    # Definir la ruta de descarga y el archivo ZIP
    $zipFile = "C:\Temp\apache-tomcat-$tomcatVersion.zip"

    if ($downloadMethod -eq "1") {
        # Descargar desde la web oficial
        if ($tomcatVersion -like "10.*") {
            $downloadUrl = "https://dlcdn.apache.org/tomcat/tomcat-10/v$tomcatVersion/bin/apache-tomcat-$tomcatVersion-windows-x64.zip"
        } elseif ($tomcatVersion -like "11.*") {
            $downloadUrl = "https://dlcdn.apache.org/tomcat/tomcat-11/v$tomcatVersion/bin/apache-tomcat-$tomcatVersion-windows-x64.zip"
        } else {
            Write-Host "Error: Versión de Tomcat no válida."
            return
        }

        Write-Host "Descargando Tomcat $tomcatVersion desde la web oficial..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile
    } elseif ($downloadMethod -eq "2") {
        # Descargar desde el servidor FTP
        Write-Host "Navegando por el servidor FTP para seleccionar el archivo de Tomcat..."
        Navegar-FTP

        # Verificar si el archivo seleccionado existe
        if (!(Test-Path $zipFile)) {
            Write-Host "Error: No se encontró el archivo descargado."
            return
        }
    } else {
        Write-Host "Opción no válida. Saliendo..."
        return
    }

    # Rutas de instalación
    $installPath = "C:\Tomcat\apache-tomcat-$tomcatVersion"
    $serviceName = "Tomcat$($tomcatVersion.Split('.')[0])"
    $serverXmlPath = "$installPath\conf\server.xml"

    # Verificar si el servicio ya existe
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Write-Host "El servicio $serviceName ya existe. Saliendo..."
        return
    }

    # Extraer archivos
    Write-Host "Extrayendo archivos..."
    Expand-Archive -Path $zipFile -DestinationPath "C:\Tomcat" -Force

    # Verificar que server.xml exista
    if (!(Test-Path $serverXmlPath)) {
        Write-Host "Error: No se encontró server.xml."
        return
    }

    # Configurar el puerto HTTP
    (Get-Content $serverXmlPath) -replace 'port="8080"', "port=`"$port`"" | Set-Content $serverXmlPath

    # Agregar configuración SSL dentro de `<Service>` correctamente
    $httpsPort = $port + 100
    Write-Host "Configurando SSL en el puerto $httpsPort..."

    $sslConfig = @"
<Connector port="$httpsPort" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="200"
           SSLEnabled="true">
    <SSLHostConfig>
        <Certificate certificateKeystoreFile="conf/tomcat.keystore"
                     type="RSA"
                     certificateKeystorePassword="MiClaveSSL"/>
    </SSLHostConfig>
</Connector>
"@

    # Insertar el bloque SSL antes de `</Service>`
    (Get-Content $serverXmlPath) -replace '</Service>', "$sslConfig`n</Service>" | Set-Content $serverXmlPath

    # Generar el keystore solo si no existe
    $keystorePath = "$installPath\conf\tomcat.keystore"
    if (!(Test-Path $keystorePath)) {
        Write-Host "Generando el keystore SSL..."
        $pfxFile = "C:\Temp\tomcat.pfx"
        $certThumbprint = "74178FEF3C759C17538FF26D10B83BA051E0F27E"

        $cert = Get-Item "Cert:\LocalMachine\My\$certThumbprint" -ErrorAction SilentlyContinue
        if ($cert) {
            Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password (ConvertTo-SecureString -String "MiClaveSSL" -AsPlainText -Force)

            # Convertir PFX a Java Keystore
            $javaHome = [System.Environment]::GetEnvironmentVariable("JAVA_HOME", "Machine")
            $keytool = "$javaHome\bin\keytool.exe"
            if (Test-Path $keytool) {
                Start-Process -NoNewWindow -FilePath $keytool -ArgumentList @(
                    "-importkeystore",
                    "-srckeystore `"$pfxFile`"",
                    "-srcstoretype PKCS12",
                    "-srcstorepass MiClaveSSL",
                    "-destkeystore `"$keystorePath`"",
                    "-deststoretype JKS",
                    "-deststorepass MiClaveSSL"
                ) -Wait
                Write-Host "Keystore generado correctamente."
            } else {
                Write-Host "Error: No se encontró keytool.exe en JAVA_HOME."
            }
        } else {
            Write-Host "Error: No se encontró el certificado con la huella especificada."
        }
    } else {
        Write-Host "El keystore ya existe, omitiendo creación."
    }

    # Verifica si web.xml existe; si no, lo crea vacío con web-app
    $webXmlPath = "$installPath\webapps\ROOT\WEB-INF\web.xml"
    if (!(Test-Path $webXmlPath)) {
        New-Item -Path $webXmlPath -ItemType File -Force | Out-Null
        Set-Content -Path $webXmlPath -Value "<?xml version=`"1.0`" encoding=`"UTF-8`"?>`n<web-app></web-app>"
    }

    # Agregar security-constraint DENTRO de <web-app>, si no está presente
    $securityConfig = @"
<security-constraint>
    <web-resource-collection>
        <web-resource-name>Protected Context</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <user-data-constraint>
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>
    </user-data-constraint>
</security-constraint>
"@

    # Insertarlo dentro de <web-app> si no está presente
    if (-not (Select-String -Path $webXmlPath -Pattern "<security-constraint>" -Quiet)) {
        (Get-Content $webXmlPath) -replace '</web-app>', "$securityConfig`n</web-app>" | Set-Content $webXmlPath
    } else {
        Write-Host "La configuración de seguridad ya está en web.xml."
    }

    # Instalar y empezar el servicio
    Write-Host "Instalando el servicio $serviceName..."
    cd "$installPath\bin"
    .\service.bat install $serviceName

    Start-Service -Name $serviceName
    Write-Host "Tomcat $tomcatVersion ha sido instalado y configurado en HTTPS $httpsPort."
}


function Install-Nginxssl {
    param (
        [string]$nginxDescargas = "https://nginx.org/en/download.html"
    )

    # Obtener la página de descargas de Nginx
    $paginaNginx = (Invoke-WebRequest -Uri $nginxDescargas -UseBasicParsing).Content

    # Expresión regular para encontrar versiones de Nginx
    $versionRegex = 'nginx-(\d+\.\d+\.\d+)\.zip'

    # Encontrar todas las versiones en la página
    $versiones = [regex]::Matches($paginaNginx, $versionRegex) | ForEach-Object { $_.Groups[1].Value }

    # Asignar versiones LTS y de desarrollo
    $versionLTSNginx = $versiones[6]  
    $versionDevNginx = $versiones[0]  

    # Menú de selección de versión
    echo "Instalador de Nginx"
    echo "1. Versión LTS $versionLTSNginx"
    echo "2. Versión de desarrollo $versionDevNginx"
    echo "3. Salir"
    $opcNginx = Read-Host "Selecciona una versión"

    switch ($opcNginx) {
        "1" {
            $port = Get-ValidPort
            Install-NginxVersionssl -version $versionLTSNginx -port $port
        }
        "2" {
            $port = Get-ValidPort
            Install-NginxVersionssl -version $versionDevNginx -port $port
        }
        "3" {
           return
        }
        default {
            echo "Seleccione una opción válida..."
        }
    }
}

function Install-NginxVersionssl {
    param (
        [string]$version,
        [int]$port
    )

    try {
        # Detener Nginx si está corriendo
        Stop-Process -Name nginx -ErrorAction SilentlyContinue

        # Crear carpeta C:\nginx si no existe
        if (-not (Test-Path "C:\nginx")) {
            New-Item -ItemType Directory -Path "C:\nginx"
        }

        # Descargar e instalar Nginx
        Write-Host "Instalando versión $version..."
        $downloadUrl = "https://nginx.org/download/nginx-$version.zip"
        $zipFile = "C:\nginx\nginx-$version.zip"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
        Expand-Archive -Path $zipFile -DestinationPath "C:\nginx" -Force

        # Definir rutas
        $nginxDir = "C:\nginx\nginx-$version"
        $nginxConfigPath = "$nginxDir\conf\nginx.conf"
        $pfxFile = "$nginxDir\conf\nginx.pfx"
        $sslCertPath = "$nginxDir\conf\certificado.pem"
        $sslKeyPath = "$nginxDir\conf\certificado.key"

        # Configurar el puerto HTTP en nginx.conf
        $nginxConfig = Get-Content $nginxConfigPath

        # Modificar el bloque server para el puerto HTTP
        $nginxConfig = $nginxConfig -replace "listen\s+\d+;", "listen $port;"

        # Definir el puerto HTTPS
        $httpsPort = $port + 100
        Write-Host "Configurando SSL en el puerto $httpsPort..."

        # Generar certificado SSL si no existe
        $certThumbprint = "8492C08EA49780DF8036679F7DA9243C15B5AF09"

        if (!(Test-Path $pfxFile)) {
            Write-Host "Generando certificado SSL..."
            $cert = Get-Item "Cert:\LocalMachine\My\$certThumbprint" -ErrorAction SilentlyContinue
            if ($cert) {
                Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password (ConvertTo-SecureString -String "MiClaveSSL" -AsPlainText -Force)

                # Buscar OpenSSL
                $opensslPath = (Get-Command openssl -ErrorAction SilentlyContinue).Source
                if ($opensslPath) {
                    Start-Process -NoNewWindow -FilePath $opensslPath -ArgumentList @(
                        "pkcs12", "-in", "`"$pfxFile`"", "-out", "`"$sslCertPath`"", "-clcerts", "-nokeys", "-password", "pass:MiClaveSSL"
                    ) -Wait
                    Start-Process -NoNewWindow -FilePath $opensslPath -ArgumentList @(
                        "pkcs12", "-in", "`"$pfxFile`"", "-nocerts", "-out", "`"$sslKeyPath`"", "-nodes", "-password", "pass:MiClaveSSL"
                    ) -Wait
                    Write-Host "Certificado convertido correctamente."
                } else {
                    Write-Host "Error: No se encontró OpenSSL. SSL no configurado."
                    return
                }
            } else {
                Write-Host "Error: No se encontró el certificado con la huella especificada."
                return
            }
        } else {
            Write-Host "El certificado ya existe, omitiendo creación."
        }

        # Insertar configuración SSL dentro del bloque server
        $nginxConfig = $nginxConfig -replace "(server\s*{[^}]*listen\s+$port;)", "`$1`n    listen $httpsPort ssl;`n    ssl_certificate $sslCertPath;`n    ssl_certificate_key $sslKeyPath;"

        # Guardar cambios en nginx.conf
        Set-Content -Path $nginxConfigPath -Value $nginxConfig

        # Iniciar Nginx
        Start-Process -NoNewWindow -FilePath "$nginxDir\nginx.exe" -ArgumentList "-p `"$nginxDir`""

        # Verificar que Nginx esté en ejecución
        $nginxProcess = Get-Process | Where-Object { $_.ProcessName -like "*nginx*" }
        if ($nginxProcess) {
            Write-Host "Nginx está en ejecución."
        } else {
            Write-Host "Error: Nginx no se inició correctamente."
            return
        }

        # Verificar que el puerto HTTPS esté escuchando
        Write-Host "Verificando si el puerto HTTPS $httpsPort está escuchando..."
        try {
            $httpsPortListening = Test-NetConnection -ComputerName localhost -Port $httpsPort -ErrorAction Stop
            if ($httpsPortListening.TcpTestSucceeded) {
                Write-Host "Nginx está corriendo correctamente en https://localhost:$httpsPort"
            } else {
                Write-Host "Error: El puerto HTTPS $httpsPort no está escuchando. Revisa la configuración de Nginx."
            }
        } catch {
            Write-Host "Error: No se pudo verificar el puerto HTTPS $httpsPort. Asegúrate de que sea un puerto válido."
        }
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)"
    }
}



function Install-IISssl {
    # Verificar si IIS está instalado
    $iisFeature = Get-WindowsFeature -Name Web-Server
    if ($iisFeature.Installed -eq $false) {
        Write-Host "IIS no está instalado. Instalando..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools -NoProgress
    } else {
        Write-Host "IIS ya está instalado."
    }

    # Obtener un puerto válido
    $port = Get-ValidPort

    # Validar que el puerto sea válido antes de continuar
    if ($port -lt 1 -or $port -gt 65535) {
        Write-Host "Error: El puerto $port no es válido. Debe estar entre 1 y 65535."
        return
    }

    # Iniciar el servicio IIS si no está corriendo
    if ((Get-Service -Name W3SVC).Status -ne "Running") {
        Write-Host "Iniciando el servicio IIS..."
        Start-Service -Name W3SVC
    }

    # Importar módulo de administración web
    Import-Module WebAdministration

    # Verificar si el sitio predeterminado existe
    $defaultSite = Get-WebSite -Name "Default Web Site" -ErrorAction SilentlyContinue
    if ($defaultSite) {
        Write-Host "El sitio 'Default Web Site' ya existe. Configurando..."
        Stop-WebSite -Name "Default Web Site"

        # Verificar si hay un binding en el puerto 80 antes de eliminarlo
        $binding80 = Get-WebBinding -Name "Default Web Site" | Where-Object { $_.bindingInformation -eq "*:80:" }
        if ($binding80) {
            Remove-WebBinding -Name "Default Web Site" -BindingInformation "*:80:"
        }

        # Verificar si el binding en el nuevo puerto ya existe antes de agregarlo
        $existingBinding = Get-WebBinding -Name "Default Web Site" | Where-Object { $_.bindingInformation -match "\*:$($port):" }
        if (-not $existingBinding) {
            New-WebBinding -Name "Default Web Site" -Protocol http -Port $port
        } else {
            Write-Host "El sitio ya tiene un binding en el puerto $port."
        }

        Start-WebSite -Name "Default Web Site"
    } else {
        Write-Host "No se encontró 'Default Web Site'. Creándolo..."
        New-WebSite -Name "Default Web Site" -Port $port -PhysicalPath "C:\inetpub\wwwroot"
    }

    # Verificar si el puerto está escuchando
    Write-Host "Verificando si el puerto $port está escuchando..."
    try {
        $portListening = Test-NetConnection -ComputerName localhost -Port $port -ErrorAction Stop
        if ($portListening.TcpTestSucceeded) {
            Write-Host "IIS está corriendo correctamente en http://localhost:$port"
        } else {
            Write-Host "Error: El puerto $port no está escuchando. Revisa la configuración de IIS."
        }
    } catch {
        Write-Host "Error: No se pudo verificar el puerto $port. Asegúrate de que sea un puerto válido."
    }

    # Configurar SSL para IIS
    Write-Host "Configurando SSL para IIS..."
    $httpsPort = $port + 100
    $certThumbprint = "8BC8D68FD28472D2301DD77565A0DEE42DDB625E"

    # Verificar si el certificado ya existe
    $cert = Get-Item "Cert:\LocalMachine\My\$certThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        Write-Host "Error: No se encontró el certificado con la huella especificada."
        return
    }

    # Exportar el certificado a un archivo PFX
    $pfxFile = "C:\Temp\iis_cert.pfx"
    $pfxPassword = ConvertTo-SecureString -String "MiClaveSSL" -AsPlainText -Force
    Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $pfxPassword

    # Importar el certificado al almacén de certificados de IIS
    Import-PfxCertificate -FilePath $pfxFile -CertStoreLocation Cert:\LocalMachine\My -Password $pfxPassword

    # Agregar el binding HTTPS al sitio
    $bindingInfo = "*:$($httpsPort):"
    $existingHttpsBinding = Get-WebBinding -Name "Default Web Site" | Where-Object { $_.bindingInformation -eq $bindingInfo }
    if (-not $existingHttpsBinding) {
        # Especificar el nombre de host como "localhost" y SSLFlags = 0
        New-WebBinding -Name "Default Web Site" -Protocol https -Port $httpsPort -HostHeader "localhost" -SslFlags 0
        Write-Host "Binding HTTPS agregado en el puerto $httpsPort."
    } else {
        Write-Host "El sitio ya tiene un binding HTTPS en el puerto $httpsPort."
    }

    # Verificar si el puerto HTTPS está escuchando
    Write-Host "Verificando si el puerto HTTPS $httpsPort está escuchando..."
    try {
        $httpsPortListening = Test-NetConnection -ComputerName localhost -Port $httpsPort -ErrorAction Stop
        if ($httpsPortListening.TcpTestSucceeded) {
            Write-Host "IIS está corriendo correctamente en https://localhost:$httpsPort"
        } else {
            Write-Host "Error: El puerto HTTPS $httpsPort no está escuchando. Revisa la configuración de IIS."
        }
    } catch {
        Write-Host "Error: No se pudo verificar el puerto HTTPS $httpsPort. Asegúrate de que sea un puerto válido."
    }
}

function Navegar-FTP {
    param (
        [string]$ftpServer = "192.168.0.224",
        [string]$ftpUser = "anonymous",  # Usuario anónimo
        [string]$ftpPassword = ""        # Contraseña vacía para usuario anónimo
    )

    # Ruta inicial en el servidor FTP
    $rutaActual = "/Servidores"

    while ($true) {
        Clear-Host
        Write-Host "Navegando por FTP: $rutaActual"
        Write-Host "--------------------------------"

        # Listar carpetas y archivos en la ruta actual
        try {
            # Crear una sesión FTP con SSL/TLS y aceptar certificados autofirmados
            $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
                Protocol = [WinSCP.Protocol]::Ftp
                HostName = $ftpServer
                UserName = $ftpUser
                Password = $ftpPassword
                FtpSecure = [WinSCP.FtpSecure]::Explicit
                GiveUpSecurityAndAcceptAnyTlsHostCertificate = $true
            }

            $session = New-Object WinSCP.Session
            $session.Open($sessionOptions)

            # Obtener la lista de archivos y carpetas
            $listaArchivos = $session.ListDirectory($rutaActual).Files

            if ($listaArchivos.Count -eq 0) {
                Write-Host "No se encontraron archivos o carpetas en esta ubicación."
                Read-Host "Presione Enter para volver..."
                return
            }

            # Mostrar carpetas y archivos
            Write-Host "1. Salir"
            $contador = 2
            $opciones = @{}
            $tipoElemento = @{}

            foreach ($archivo in $listaArchivos) {
                $nombre = $archivo.Name

                if ($archivo.IsDirectory) {
                    Write-Host "$contador. [Carpeta] $nombre"
                    $opciones[$contador] = $nombre
                    $tipoElemento[$contador] = "carpeta"
                } else {
                    Write-Host "$contador. [Archivo] $nombre"
                    $opciones[$contador] = $nombre
                    $tipoElemento[$contador] = "archivo"
                }
                $contador++
            }

            Write-Host "--------------------------------"
            $seleccion = [int] (Read-Host "Seleccione una opción (1-$(($contador - 1)))")

        if ($seleccion -eq 1) {
                # Salir de la función
                Write-Host "Saliendo del navegador FTP..."
                return
            } elseif ($opciones.ContainsKey($seleccion)) {
                $elementoSeleccionado = $opciones[$seleccion]
                $tipo = $tipoElemento[$seleccion]

                if ($tipo -eq "carpeta") {
                    # Es una carpeta, navegar a ella
                    $rutaActual = "$rutaActual/$elementoSeleccionado"
                } else {
                    # Es un archivo, preguntar si desea descargarlo
                    $confirmacion = Read-Host "¿Desea descargar el archivo $elementoSeleccionado? (s/n)"
                    if ($confirmacion -eq "s" -or $confirmacion -eq "S") {
                        $rutaDestino = "C:\FTP-Descargas"
                        if (!(Test-Path -Path $rutaDestino)) {
                            New-Item -ItemType Directory -Path $rutaDestino | Out-Null
                        }
                        Write-Host "Descargando $elementoSeleccionado a $rutaDestino..."
                        # Descargar el archivo
                        $session.GetFiles("$rutaActual/$elementoSeleccionado", "$rutaDestino\$elementoSeleccionado").Check()
                        Write-Host "Descarga completada en: $rutaDestino\$elementoSeleccionado"
                        Read-Host "Presione Enter para continuar..."
                    }
                }
            } else {
                Write-Host "Opción no válida."
                Read-Host "Presione Enter para continuar..."
            }

        } catch {
            Write-Host "Error: $_"
            Read-Host "Presione Enter para continuar..."
        } finally {
            if ($session -ne $null) {
                $session.Dispose()
            }
        }
    }
}
