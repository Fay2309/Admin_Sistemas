#Get-Member: Información de un objeto
Get-Service -Name "LSM" | Get-Member

#Get-Membet, propiedades de un objeto 
Get-Service -Name "LSM" | Get-Member -MemberType Property

#Get-Member: Información sobre los métodos de un objeto
Get-Item .\test.txt | Get-Member -MemberType Method


#Select-Object: Filtrado de columnas 
Get-Item .\test.txt | Select-Object Name, Length

#Select-Object: Obtener las últimas 5 filas 
Get-Service | Select-Object -Last 5 

#Select-Object: Obtener las primeras 5 filas 
Get-Service | Select-Object -First 5 


#Where-Object: Filtrado por estado
Get-Service | Where-Object {$_.Status -eq "Running"}

#Acceso a los atributos de un objeto 
(Get-Item .\test.txt).IsReadOnly
(Get-Item .\test.txt).IsReadOnly = 1
(Get-Item .\test.txt).IsReadOnly


#Los métodos 
#Ejemplos de uso de métodos de un objeto 
Get-ChildItem *.txt

#Ejemplo de uso de métodos de un objeto
(Get-Item .\test.txt).CopyTo("D:\Desktop\prueba.txt")
(Get-Item .\test.txt).Delete()
Get-ChildItem *.txt

#Expansión de un objetod de forma dinámica
$miObjeto = New-Object PSObject
$miObjeto | Add-Member -MemberType NoteProperty -Name Nombre -Value "Miguel"
$miObjeto | Add-Member -MemberType NoteProperty -Name Edad -Value 23
$miObjeto | Add-Member -MemberType ScriptMethod -Name Saludar -Value {Write-Host "Hola Mundo!"}

#Adicion de propiedades utilizando una "Hash Table"
$miObjeto = New-Object -TypeName psobject -Property @{
    Nombre = "Miguel"
    Edad = 23
}

$miObjeto | Add-Member -MemberType ScriptMethod -Name Saludar -Value {Write-Host "Hola Mundo!"}
$miObjeto | Get-Member

#Creación de objeto utilizando el acelerador de tipo PSCustomObject
$miObjeto = [PSCustomObject]@{
    Nombre = "Miguel"
    Edad = 23
}
$miObjeto | Add-Member -MemberType ScriptMethod -Name Saludar -Value {Write-Host "Hola Mundo!"}
$miObjeto | Get-Member

#Parar un proceso usando pipelines y cmdlets 
Get-Process -Name Acrobat | Stop-Process

#Salidas de Get-Process
Gel-Help -Full Get-Process

#Entradas de Stop-Process 
Get-Help -Full Stop-Process

#Muestras del funcionamiento de la ejecución 
Get-Process
Get-Process -Name Acrobat | Stop-Process
Get-Process

#Salidas de Get-ChildItem; Entradas de Get-ClipBoard; Error de canalización de pipes
Get-Help -Full Get-ChildItem
Get-Help -Full Get-Clipboard
Get-ChildItem *.txt | Get-Clipboard

#Entradas de cmdlet Get-Help
Get-Help -Full Stop-Service

#Primer ejemplo de canalización por valor 
Get-Service
Get-Service Spooler | Stop-Service
Get-Service

#Segundo ejemplo de canalización por valor 
Get-Service
"Spooler" | Stop-Service
Get-Service

#Ejmplo de canalización por nombre 
Get-Service
$miObjeto = [PSCustomObject]@{
    Name = "Spooler"
}
$miObjeto | Stop-Service
Get-Service

