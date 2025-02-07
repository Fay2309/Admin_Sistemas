#Lista de verbos aprobados, usando el comando cmdlet Get-Verb
Get-Verb

Write-Output " "


#Ejemplo de una función simple que nos devuelve la hora
function Get-Fecha {
    Get-Date
}
Get-Fecha

#Ejecución del comando para encontrar la fucnión creada en el ejemplo anterior
Get-ChildItem -Path function:\Get-*

#Ejecución del comando de borrado
Get-ChildItem -Path Function:\Get-Fecha | Remove-Item
Get-ChildItem -Path Function:\Get-* 

#Ejemplo de función básica con parámetros especificando el tipo de datos
function Get-Resta {
    param ([int]$num1, [int]$num2) 
    $resta = $num1 - $num2
    Write-Output "La resta de los parametros es $resta"
}
Get-Resta 10 5

Write-Output " "

#Ejecución de una función básica con parámetros nombrados 
Get-Resta -num2 10 -num1 5

Write-Output " "

#Ejecución de una fucnión básica con parámetros opcionales 
Get-Resta -num2 10 

Write-Output " "

#Ejemplo de una función básica con parámetro requerido
function Get-Resta2 {
    Param ([Parameter(Mandatory)][int]$num3, [int]$num4)
    $resta2 = $num3-$num4
    Write-Output "La resta de los parametros es $resta2"
}
Get-Resta2 -num3 10

Write-Output " "

#Ejemplo de función avanzada - CmdletBinding() agrega los parámetros comunes, por ejemplo, los obligatorios
function Get-Resta3 {
    [CmdletBinding()]
    Param ([int]$num5, [int]$num6)
    $resta3=$num5-$num6
    Write-Output "La resta de los parametros es $resta3"
}
Get-Resta3

Write-Output " "

#Uso del comando Get-Command para mostrar todos los parámetros de la función
(Get-Command -Name Get-Resta).Parameters.Keys

#Ejemplo de una función de con un comentario 
function Get-Resta4 {
    [CmdletBinding()]
    Param ([int]$num1, [int]$num2)
    $resta4=$num7-$num8 #Operación que realiza la resta
    Write-Output "La resta de los parametros es $resta4"
}

Write-Output " "

#Ejemplo de una fucnión con Write-Verbose
function Get-Resta5 {
    [CmdletBinding()]
    Param ([int]$num9, [int]$num10)
    $resta5=$num9-$num10
    Write-Verbose -Message "Operacion que va a realizar una resta de $num9 y $num10"
    Write-Host "La resta de los parametros es $resta5"
}
Get-Resta5 10 5 -Verbose