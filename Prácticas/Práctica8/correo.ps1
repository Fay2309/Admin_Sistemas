# La creación de usuarios se hace mediante Mercury ($mercryFolder = "C:\Mercury\MAIL" (crear carpeta de usuario) y luego $mercryFolder = "C:\Mercury\Mercury.ini" colocar usuario y su contraseña)
# Es necesario descargar XAMPP de manera externa e iniicar Apache
# Es necesario mantener Mercury abierto, al igual que XAMPP
# Es necesario deshabilitar IIS, ya que causa conflicto con XAMPP, que es necesario para el funcionamiento de Squirrelmail.
. "C:\Users\Administrador\Documents\Scripts\Funciones.ps1"

try {
    InstallMercury
    Install-SquirrelMail

    Write-Host "`nInstalación completada exitosamente!" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Cyan
    Write-Host "Los usuarios se crean en Mercury" -ForegroundColor Green
    Write-Host "Dominio: $domain" -ForegroundColor Green
    Write-Host "Puertos abiertos: SMTP (25), POP3 (110), IMAP (143)" -ForegroundColor Cyan
    Write-Host "SquirrelMail en: http://$($env:COMPUTERNAME)/webmail" -ForegroundColor Green
}
catch {
    Write-Host "`nError durante la instalación: $_" -ForegroundColor Red
    exit 1
}
