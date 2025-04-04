#!/bin/bash

source "/home/gael/Desktop/Scripts/Funciones (Copy).sh"

main() {
    echo "Iniciando instalación y configuración de servicios de correo..."
    
    instalar_servicios
    configurar_dominio_postfix
    instalar_squirrelmail
    crear_usuarios_mailbox
    verificar_servicios
    mostrar_info
    
    echo "Proceso completado. Puedes acceder a SquirrelMail en http://$(hostname)/squirrelmail"
}

main
