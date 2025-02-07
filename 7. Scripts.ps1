#Ejemplo de bloque try/catch
try {
    Write-Output "Todo bien"
}
catch {
    Write-Output "Algo lanzo una excepcion"
    Write-Output $_
}

try {
    Start-Something -ErrorAction Stop
}
catch {
    Write-Output "Algo genero una excepcion o uso un Write-Error"
}

#Ejemplo de bloque Try/Finally
# $comando = [System.Data.SqlClient.SqlCommand]::New(queryString, connection)
# try {
#     $comando.Connection.Open()
#     $comando.ExecuteNonQuery()
# }
# finally {
#     Write-Error "Ha habido un problma con la ejecucion de la query. Cerrando la conexion"
#     $comando.Connection.Close()
# }

#Recogida de varios tipos de excepción distintos
try {
    Start-Something -Path $path -ErrorAction Stop
}
catch [System.IO.DirectoryNotFoundException], [System.IO.FileNotFoundException]{
    Write-Output "El directorio o fichero no ha sido encontrado: [$path]"
}
catch [System.IO.IOException] {
    Write-Output "Error de IO con el archivo: [$path]"
}

#Diversas formas de lanzar una exepción
throw "No se puede encontrar la ruta: [$path]"

throw [System.IO.FileNotFoundException] "No se puede encontrar la ruta: [$path]"

throw [System.IO.FileNotFoundException]::New()

throw [System.IO.FileNotFoundException]::New("No se puede encontrar la ruta: [$path]")

throw (New-Object -TypeName System.IO.FileNotFoundException)

throw (New-Object -TypeName System.IO.FileNotFoundException -ArgumentList "No se puede encontrar la ruta [$path]")

#Ejemplo de uso de trap
trap {
    Write-Output $PSItem.ToString()
}
throw [System.Exception]::New("Primero")
throw [System.Exception]::New("Segundo")
throw [System.Exception]::New("Tercero")

#Importación del modulo
#ls
#Import-Module BackupRegistry

#Función ya importada
Get-Help Backup-Registry

#Comprobación del funcion exportado
Backup-Registry -rutaBackup 'D:\'

#Comprobación de la eliminación automática de backups
vim .\Backup-Registry.ps1
Import-Module BackupRegistry -Force
Backup-Registry -rutaBackup 'D:\'

#Comprobación de ejecución del script de forma automática
# ls 'D:\'
# Get-Date
# ls 'D:\'

#Lista de tareas programadas 
Get-ScheduledTask

#Eliminar tarea programada
Unregister-ScheduledTask "Ejecutar Backup dentro del sistema"

#Volver a listar las tareas programadas 
Get-ScheduledTask

