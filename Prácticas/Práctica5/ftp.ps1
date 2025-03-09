. "C:\Users\Administrador\Documents\Scripts\Funciones.ps1"

#FTP

while ($true) {
    Write-Host "`nOpciones:"
    Write-Host "1) Crear Usuario FTP"
    Write-Host "2) Operaciones extra (Cambiar/Eliminar)"
    Write-Host "3) Salir"

    $opcion = Read-Host "Seleccione una opción..."

    switch ($opcion) {
        "1" {
            Crear-UsuarioFTP
        }
        "2" {
            Operations
        }
        "3" {
            Write-Host "Saliendo..."
            exit
        }
        default {
            Write-Host "Opción no válida. Intente de nuevo..."
        }
    }
}
