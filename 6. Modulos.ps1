#Ejecución del comando Get-Module
Get-Module

#Ejecución del comando Get-Module -ListAvailable
Get-Module -ListAvailable

#Ejemplo de borrado de módulo
Get-Module
Remove-Module BitsTransfer
Get-Module 

#Ejecución del comando Get-Command
Get-Command -Module BitsTransfer

#Ejecución del comando Get-Help
Get-Help BitsTransfer

#Ejecución del comando PSModulePath - Importación de un modulo no instalado
#$env:PSModulePath #Ruta

#Ejemplo de como importar un módulo
Import-Module BitsTransfer
Get-Module

