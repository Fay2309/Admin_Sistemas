#!/bin/bash

source "/home/gael/Desktop/Scripts/Funciones.sh"

# Llamar primero a FTP al iniciar el programa
FTP

while true; do
    echo "Opciones:"
    echo "1) Crear Usuario FTP"
    echo "2) Eliminar Usuario FTP"
    echo "3) Cambiar grupo de usuario FTP"
    echo "4) Salir"
    read -p "Seleccione una opción: " opcion

    case "$opcion" in
        1) 
            read -p "Ingrese el nombre del usuario: " nombreUsuario
            Crear-UsuarioFTP "$nombreUsuario"
            ;;
        2) 
            read -p "Ingrese el nombre del usuario a eliminar: " nombreUsuario
            Eliminar-UsuarioFTP "$nombreUsuario"
            ;;
        3) 
            read -p "Ingrese el nombre del usuario a cambiar de grupo: " nombreUsuario
            Cambiar-GrupoFTP "$nombreUsuario"
            ;;
        4) exit 0 ;;
        *) echo "Opción no válida." ;;
    esac
done
