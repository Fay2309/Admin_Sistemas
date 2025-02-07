#Listado de los Cmdlets del sistema
Get-Command -Type Cmdlet | Sort-Object -Property Noun | Format-Table -GroupBy Noun

#Obtener la Sintaxix de un cmdlet
Get-Command -Name Get-ChildItem -Args Cert: -Syntax

#Obtener el cmdlet de un alias 
Get-Command -Name dir

#Cmdlets de un recurso especifico 
Get-Command -Noun WSManInstance
