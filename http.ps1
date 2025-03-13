. "C:\Users\Administrador\Documents\Scripts\Funciones.ps1"

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
            $tomcatVersion = Get-TomcatVersion
            $port = Get-ValidPort
            Install-Tomcat -tomcatVersion $tomcatVersion -port $port
        }
        "2" {Install-Nginx}
        "3" {Install-IIS}
        "4" { exit }
        default { Write-Host "Opción no válida, intente nuevamente." }
    }
    Read-Host "Presione Enter para continuar..."
}