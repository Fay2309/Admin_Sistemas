#Condicional IF básica
$condicion = $true
if ($condicion){
    Write-Output "La condicion era verdadera"
}
else {
    Write-Output "La condicion era falsa"
}

#Condicional elseif básico
$numero = 2
if($numero -ge 3 ) {
    Write-Output "El numero [$numero] es mayor o igual que 3"
}
elseif ($numero -lt 2) {    
    Write-Output "El numero [$numero] es menor que 2"
}
else {
    Write-Output "El numero [$numero] es igual a 2"
}

$PSVersionTable

#OPERADOR TERNARIO
#$mensaje = (Test-Path $path) ? "Path existe" : "Path no encontrado"
#$mensaje

#Condicional Switch
#Coincidencia con un número
switch (3) {
    1 {"[$_] es uno"  }
    2 {"[$_] es dos"  }
    3 {"[$_] es tres"  }
    4 {"[$_] es cuatro"  }
}
#Coincidencia con varios números
switch (3) {
    1 {"[$_] es uno"  }
    2 {"[$_] es dos"  }
    3 {"[$_] es tres"  }
    4 {"[$_] es cuatro"  }
    3 {"[$_] tres de nuevo"  }
}

#Coincidencia con varios números pero con break
switch (3) {
    1 {"[$_] es uno"  }
    2 {"[$_] es dos"  }
    3 {"[$_] es tres" ; Break }
    4 {"[$_] es cuatro"  }
    3 {"[$_] tres de nuevo"  }
}

#Evaluación de varios valores 
switch (1, 5) {
    1 {"[$_] es uno"  }
    2 {"[$_] es dos"  }
    3 {"[$_] es tres" ; Break }
    4 {"[$_] es cuatro"  }
    5 {"[$_] es cinco"  }
}

#Intento de coincidencia con parámetro WildCard (string)
switch ("seis") {
    1 {"[$_] es uno"  ; Break }
    2 {"[$_] es dos" ; Break }
    3 {"[$_] es tres" ; Break }
    4 {"[$_] es cuatro" ; Break }
    5 {"[$_] es cinco" ; Break }
    "se*" {"$[_] conincide con se*."}
    Default {
        "No hay coincidencias con [$_]"
    }
}

#Intento de coincidencia con parámetro WildCard (string)
switch -Wildcard ("seis") {
    1 {"[$_] es uno"  ; Break }
    2 {"[$_] es dos" ; Break }
    3 {"[$_] es tres" ; Break }
    4 {"[$_] es cuatro" ; Break }
    5 {"[$_] es cinco" ; Break }
    "se*" {"[$_] conincide con se*."}
    Default {
        "No hay coincidencias con [$_]"
    }
}

#Coincidencia utilzando el parámetro REGEX. Uso de $matches
$email = 'antonio.yanez@udc.es'
$email2 = 'antonio.yanez@usc.gal'
$url = 'https://www.dc.fi.udc.es/-afyanez/Docencia/2023'
switch -Regex ($url, $email, $email2) {
    '^\w+\.\w+@(udc|usc|edu)\.es|gal$' {"[$_] es una direccion de correo electronico academica"}

    '^ftp\://.*$' {"[$_] es una direccion ftp"}
    '^(http[s]?)\://.*$' {"[$_] es una direccion web, que utiliza [$($matches[1])]"}
}
Write-Output " "

#Opereadores lógicos
#Igual - Se hace una conversión del valor de la derecha al de la izquierda
#En la primera se transforma de String a Int, en la segunda de Int a String
1 -eq "1.0"
"1.0" -eq 1
Write-Output " "

#Bucles
#Bucle for, asignación múltiples por comas
for (($i = 0), ($j = 0); $i -lt 5; $i++) {
    "`$i:$i"
    "`$j:$j"
}

Write-Output " "

#Bucle for, asignación y variación multiple usando subexpresiones
for (($i = 0), ($j = 0); $i -lt 5; $($i++; $j++)) {
    "`$i:$i"
    "`$j:$j"
}

Write-Output " "

#Bucle foreach, básico
$ssoo = "freebsd", "openbsd", "solaris", "fedora", "ubuntu", "netbsd"
foreach ($so in $ssoo) {
    Write-Host $so
}

Write-Output " "

#Bucle foreach, uso de cmdlets
foreach ($archivo in Get-ChildItem) {
    if ($archivo.length -ge 10KB) {
        Write-Host $archivo -> [($archivo.length)]
    }
}

Write-Output " "

#Bucle While, básico
$num = 0 

while ($num -ne 3) {
    $num++
    Write-Host $num
}

Write-Output " "

#Bucle while, uso de palabra clave
$num2 = 0

while ($num2 -ne 5) {
    if ($num2 -eq 1) {$num2 = $num2 + 3; Continue}
    $num2++
    Write-Host $num2
}

Write-Output " "

#Bucle Do-While
$valor = 5
$multiplicacion = 1

do {
    $multiplicacion = $multiplicacion * $valor
    $valor--
}
while ($valor -gt 0)
Write-Host $multiplicacion

Write-Output " "

#Bucle Do-Until, misma lógica que el anterior, pero adaptado
$valor2 = 5
$multiplicacion2 = 1

do {
    $multiplicacion2 = $multiplicacion2 * $valor2
    $valor2--
}
until ($valor2 -eq 0)
Write-Host $multiplicacion2

Write-Output " "

#Break y Continue
#Ejemplo de Break en bucle for 
$num3 = 10 
for ($i = 2; $i -lt 10; $i++) {
    $num3 = $num3+$i
    if ($i -eq 5) {Break}
}
Write-Host $num3
Write-Host $i

Write-Output " "

$cadena = "Hola, buenas tardes"
$cadena2 = "Hola, buenas noches"

switch -Wildcard ($cadena, $cadena2) {
    "Hola, buenas*" {"[$_] coincide con [Hola, buenas*]"}
    "Hola, bue*" {"[$_] coincide con [Hola, bue*]"}
    "Hola,*" {"[$_] coincide con [Hola,*] "; Break}
    "Hola, buenas tardes" {"[$_] coincide con [Hola, buenas tardes]"}
}

Write-Output " "

#Ejemplo de Continue en un bucle For 
$num4 = 10 
for ($i = 2; $i -lt 10; $i++) {
    if ($i -eq 5) {Continue}
    $num4 = $num4 + $i
}
Write-Host $num4
Write-Host $i

Write-Output " "

#Ejemplo de continue en un switch
$cadena3 = "Hola, buenas tardes"
$cadena4 = "Hola, buenas noches"

switch -Wildcard ($cadena3, $cadena4) {
    "Hola, buenas*" {"[$_] coincide con [Hola, buenas*]"}
    "Hola, bue*" {"[$_] coincide con [Hola, bue*]"; Continue}
    "Hola,*" {"[$_] coincide con [Hola,*] "}
    "Hola, buenas tardes" {"[$_] coincide con [Hola, buenas tardes]"}
}