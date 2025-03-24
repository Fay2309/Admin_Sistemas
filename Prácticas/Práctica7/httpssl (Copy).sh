#!/bin/bash

source "/home/gael/Desktop/Scripts/Funciones (Copy).sh"

while true; do
    clear
    echo "  Instalador de Servidores  "
    echo "1. Instalar Tomcat"
    echo "2. Instalar NGINX"
    echo "3. Instalar Apache"
    echo "4. Salir"
    read -p "Seleccione una opción (1-4): " opcion

    case "$opcion" in
        1)
            echo "Seleccione la versión de Tomcat:"
            echo "1) HTTP"
            echo "2) HTTPS"
            read -p "Seleccione una opción (1-2): " version_tomcat
            if [[ "$version_tomcat" == "1" ]]; then
                seleccionar_e_instalar_tomcat
            elif [[ "$version_tomcat" == "2" ]]; then
                seleccionar_e_instalar_tomcatssl
            else
                echo "Opción no válida."
            fi
            ;;
        2)
            echo "Seleccione la versión de NGINX:"
            echo "1) HTTP"
            echo "2) HTTPS"
            read -p "Seleccione una opción (1-2): " version_nginx
            if [[ "$version_nginx" == "1" ]]; then
                seleccionar_e_instalar_nginx
            elif [[ "$version_nginx" == "2" ]]; then
                seleccionar_e_instalar_nginxssl
            else
                echo "Opción no válida."
            fi
            ;;
        3)
            echo "Seleccione la versión de Apache:"
            echo "1) HTTP"
            echo "2) HTTPS"
            read -p "Seleccione una opción (1-2): " version_apache
            if [[ "$version_apache" == "1" ]]; then
                seleccionar_e_instalar_apache
            elif [[ "$version_apache" == "2" ]]; then
                seleccionar_e_instalar_apachessl
            else
                echo "Opción no válida."
            fi
            ;;
        4)
            echo "Saliendo..."
            exit 0
            ;;
        *)
            echo "Opción no válida, intente nuevamente."
            ;;
    esac

    read -p "Presione Enter para continuar..."
done
