#!/bin/bash

source "/home/gael/Desktop/Scripts/Funciones.sh"

    while true; do
        clear
        echo "  Instalador de Servidores  "
        echo "1. Instalar Tomcat"
        echo "2. Instalar NGINX"
        echo "3. Instalar Apache"
        echo "4. Salir"
        read -p "Seleccione una opción (1-4): " opcion

        case "$opcion" in
            1) versiones_tomcat ;;
            2) seleccionar_e_instalar_nginx ;;
            3) seleccionar_e_instalar_apache ;;
            4) echo "Saliendo..."; exit 0 ;;
            *) echo "Opción no válida, intente nuevamente." ;;
        esac

        read -p "Presione Enter para continuar..."
    done
