#!/bin/bash

clear
op=0

source "/home/gael/Desktop/Scripts/Funciones.sh"

while [ "$op" -eq 0 ]; do
    echo "=== Servidor SSH, ingrese las opciones que desea realizar ==="
    echo "1.- Instalar e iniciar SSH"
    echo "2.- Reiniciar SSH"
    echo "3.- Aplicar reglas de Firewall"
    echo "4.- Verificar cuentas SSH"
    echo "5.- Obtener Información de cuentas"
    echo "6.- Agregar cuentas SSH"
    echo "7.- Eliminar cuentas SSH"
    echo "8.- Salir"

    read -p "Seleccione una opción: " op2

    case $op2 in
        1)
            if systemctl list-units --type=service | grep -q "ssh.service"; then
                echo -e "\nEl servicio SSH ya está instalado, iniciando servicio..."
                sudo systemctl start ssh
                echo "Aplicando inicio automático..."
                sudo systemctl enable ssh
                echo "SSH configurado correctamente... \n"
            else
                echo "El servicio SSH no está instalado, procediendo a la instalación..."
                sudo apt update && sudo apt install -y openssh-server
                sudo systemctl start ssh
                echo "Aplicando inicio automático..."
                sudo systemctl enable ssh
                echo "SSH instalado y configurado correctamente... \n"
            fi
            ;;
        2)
            echo -e "\nReiniciando servicio SSH..."
            sudo systemctl restart ssh
            echo "Servicio SSH reiniciado correctamente..."
            ;;
        3)
            if sudo ufw status | grep -q "22/tcp"; then
                echo -e "\nLa regla ya está creada, no se creará otra vez...\n"
            else
                echo -e "\nAplicando regla SSH..."
                sudo ufw allow 22/tcp
                sudo ufw reload
                echo "Regla aplicada correctamente...\n"
            fi
            ;;
        4)
            echo -e "\nCuentas disponibles para SSH..."
            getent passwd | awk -F: '{ if ($3 >= 1000) print $1 }' | column
            ;;
        5)
            Info_User
            ;;
        6)
            Add_User
            ;;
        7)
            Delete_User
            ;;
        8)
            echo -e "\nSaliendo del script..."
            exit 0
            ;;
        *)
            echo -e "\nFavor de introducir un valor válido entre 1 y 8...\n"
            ;;
    esac
done

