#Ejemplo de uso de Get-Service - Devuelve todos los servicios del sistema
Get-Service

#Ejemplos de filtrado de servicios - Uno en concreto
Get-Service -Name Spooler
Get-Service -DisplayName Hora*

#Filtrado de servicios en ejecución
Get-Service | Where-Object {$_.Status -eq "Running"}

#Filtrado de servicios por tipo de inicio
Get-Service | Where-Object {$_.StartType -eq "Automatic"} | Select-Object Name, StartType

#Obtención de servicios que dependen del indicado 
Get-Service -DependentServices Spooler

#Obtención de dependencias 
Get-Service -RequiredServices Fax


#StopService
#Ejemplo de parada de servicio 
Stop-Service -Name Spooler -Confirm -PassThru

#Ejemplo de comienzo de servicio
Start-Service -Name Spooler -Confirm -PassThru


#SuspendService
#Ejemplo de suspensión de servicio
Suspend-Service -Name StiSvc -Confirm -PassThru

#Obtención de servicios que pueden ser suspendidos
Get-Service | Where-Object CanPauseAndContinue -eq True

#Ejemplo de intento de suspensión de un servicio que no lo permite 
Suspend-Service -Name Spooler


#RestartService
#Ejemplo de reinicio de servicio 
Restart-Service -Name WSearch -Confirm -PassThru


#SetService
#Cambio del nombre descriptivo de un servicio 
Set-Service -Name dcsvc -DisplayName "Servico de virtualizacion de credenciales de seguridad distribuidas"

#Cambio de tipo de inicio de servicio 
Set-Service -Name BITS -StartupType Automatic -Confirm -PassThru | Select-Object Name, StartType

#Cambio de descripcion de un servicio 
Set-Service -Nmae BITS -Description "Transfiere archivos en segundo plano mediante el uso de ancho de banda de red inactivo"

#Obtención de la descripción de un servicio 
Get-CimInstance Win32_Service -Filter 'Name = "BITS"' | Format-List Name, Description

#Cambio de destado de un servicio con set-Service: Iniciar Servicio 
Set-Service -Name Spooler -Status Running -Confirm -PassThru

#Cambio de estado de un servicio con set-Service: Pausar servicio
Set-Service -Name StiSvc -Status Paused -Confirm -PassThru

#Cambio de estado de un servicoi con set-service: Parar servicio 
Set-Service -Name BITS -Status Stopped -Confirm -PassThru


#Get-Process
Get-Process

#Diversos filtrados de procesos 
Get-Process -Name Acrobat
Get-Process -Name Search*
Get-Process -Id 13948

#Get-Process: Información de un módulo principal del proceso 
Get-Process WINWORD -FileVersionInfo

#Get-Process: Información del propietario del proceso
Get-Process WINWORD -IncludeUserName

#Get-Process: Información de los módulos cargados por el proceso 
Get-Process WINWORD -Module


#StopProcess
#Ejemplos de diversas formas de parado de proceso 
Stop-Process -Name Acrobat -Confirm -PassThru
Stop-Process -Id 10940 -Confirm -PassThru
Get-Process -Name Acrobat | Stop-Process -Confirm -PassThru


#StartProcess
#Start-Process: Ejemplo de parámetro -PassThru
Start-Process -FilePath "C:\WindowsS\System32\notepad.exe" -PassThru

#Start-Process: Ejemplo de parámetro -WorkingDirectory
Start-Process -FilePath "cmd.exe" -ArgumentList "/c mkdir NuevaCarpeta" -WorkingDirectory "D:\" -PassThru

#Start-Process: Ejemplo de parámetro -WindowStyle
Start-Process -FilePath "notepad.exe" -WindowStyle "Maximized" -PassThru

#Start-Process: Ejemplo de parámetro Verb
Start-Process -FilePath "D:\" -Verb Print -PassThru


#WaitProcess
#Realización de un Wait-Process por diversas vías: Nombre ; ID ; Canalización
Get-Process -Name notep*
Get-Process -Name notepad
Get-Process -Name notep*


#Administración de usuario y grupos
#Información que proporciona el cmdlet Get-LocalUser
Get-LocalUser

#Inforamción del usuario localr, filtradno por nombre 
#Get-LocalUser -Name Miguel | Select-Object *

#Información del usuairo local, filtado por SID
#Get-LocalUser -SID  S-1-5-21-619924196-4045554399-1956444398-500 | Select-Object *


#Get-LocalGroup
#Información mostrada por defecto por el cmddlet Get-LocalGroup
Get-LocalGroup

#Obtención de información de un grupo local, filtrando por nombre
Get-LocalGroup -Name Administradores | Select-Object *

#Obtención de información de un grupo local, filtrando por identificador de seguridad 
Get-LocalGroup -SID 5-1-5-32-545


#*-LocalUser
#Creación de un usuario local, sin contraseña
New-LocalUser -Name "Usuario1" -Description "Usuario de prueba" -NoPassword

#Creación de usuario local, con contraseña 
New-LocalUser -Name "Usuario2" -Description "Usuario de prueba 2" -Password (ConvertTo-String -AsPlainText "12345" -Force)

#Eliminación de usuario locales del sistema 
Get-LocalUser -Name "Usuario1"
Remove-LocalUser -Name "Usuario1"
Get-LocalUser -Name "Usuario1"


#*-LocalGroup
#Creación del grupo local
New-LocalGroup -Name "Grupo1" -Description "Grupo de prueba 1"

#Add-LocalGroupMember - Adición de un miembro a un grupo loca
Add-LocalGroupMember -Group Grupo1 -Member Usuario2 -Verbose

#Get-LocalGroupMember - Obtención de los grupos locales del sistema
Get-LocalGroupMember Grupo1

#Remove-LocalGroupMember - Elminación de miembros de un grupo
Remove-LocalGroupMember -Group Grupo1 -Member Usuario2
Get-LocalGroup Grupo1

#Remove-LocalGroup - Eliminado de un grupo local
Get-LocalGroup -Namae "Grupo1"
Remove-LocalGroup -Name "Grupo1"
Get-LocalGroup -Namae "Grupo1"

