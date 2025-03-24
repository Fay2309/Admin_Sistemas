. "C:\Users\Administrador\Documents\Scripts\Funciones.ps1"

Add-Type -Path "C:\Program Files (x86)\WinSCP\WinSCPnet.dll"

while ($true) {
    Clear-Host
    Write-Host "Instalador de Servidores"
    Write-Host "1. Instalar Tomcat"
    Write-Host "2. Instalar Nginx"
    Write-Host "3. Instalar IIS"
    Write-Host "4. Salir"
    $choice = Read-Host "Seleccione una opción (1-4)"
    
    switch ($choice) {
        "1" {
            # Preguntar al usuario si desea descargar desde la web o desde FTP
            Write-Host "Seleccione el método de descarga:"
            Write-Host "1 - Descargar desde la web oficial"
            Write-Host "2 - Descargar desde el servidor FTP"
            $downloadMethod = Read-Host "Ingrese su opción (1 o 2)"

            if ($downloadMethod -eq "1") {
                # Descargar desde la web oficial
                $tomcatVersion = Get-TomcatVersionssl
                $port = Get-ValidPort
                Install-Tomcatssl -tomcatVersion $tomcatVersion -port $port
            } elseif ($downloadMethod -eq "2") {
                # Descargar desde el servidor FTP
                Write-Host "Navegando por el servidor FTP para seleccionar el archivo de Tomcat..."
                Navegar-FTP

                # Verificar si el archivo seleccionado existe
                $zipFile = "C:\Temp\apache-tomcat-$tomcatVersion.zip"
                if (!(Test-Path $zipFile)) {
                    Write-Host "Error: No se encontró el archivo descargado."
                } else {
                    # Obtener la versión de Tomcat del nombre del archivo
                    $tomcatVersion = [System.IO.Path]::GetFileNameWithoutExtension($zipFile) -replace 'apache-tomcat-', ''
                    $port = Get-ValidPort
                    Install-Tomcatssl -tomcatVersion $tomcatVersion -port $port
                }
            } else {
                Write-Host "Opción no válida. Saliendo..."
            }
         }      
        "2" { Install-Nginxssl }
        "3" { Install-IISssl }
        "4" { exit }
        default { Write-Host "Opción no válida, intente nuevamente." }
    }
    Read-Host "Presione Enter para continuar..."
}