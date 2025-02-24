#!/bin/bash

# Validar dirección IPv4
validate_ipv4() {
    local ip=$1
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $regex ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Obtener IP válida
get_valid_ip() {
    local ip
    while true; do
        read -rp "$1: " ip
        if [[ -z "$ip" ]]; then
            echo "Error: El campo no puede estar vacío. Inténtalo de nuevo."
        elif ! validate_ipv4 "$ip"; then
            echo "Error: Dirección IP no válida. Inténtalo de nuevo."
        else
            echo "$ip"
            return
        fi
    done
}

# Calcular red y broadcast
calcular_red_broadcast() {
    local ip="$1"
    local mask="255.255.255.0"

    # Extraer los primeros tres octetos de la IP
    local base=$(echo "$ip" | awk -F. '{print $1"."$2"."$3}')

    # Asignar los valores globalmente
    network_ip="${base}.0"
    broadcast_ip="${base}.255"
}

# Calcular la máscara de subred a partir de CIDR
calcular_mascara_subred() {
    local cidr=$1

    # Inicializar la máscara de subred
    local mascara=""

    # Calcular la máscara de subred basada en el CIDR
    for i in {1..32}; do
        if [ $i -le $cidr ]; then
            mascara+="1"
        else
            mascara+="0"
        fi

        # Agregar un punto cada 8 bits
        if [ $((i % 8)) -eq 0 ] && [ $i -ne 32 ]; then
            mascara+="."
        fi
    done

    # Convertir la máscara binaria a formato decimal
    local octetos=(${mascara//./ })
    local mascara_decimal=""

    for octeto in "${octetos[@]}"; do
        mascara_decimal+=$((2#$octeto))
        mascara_decimal+="."
    done

    # Eliminar el último punto
    subnet_mask="${mascara_decimal%?}"
}

# Verificar si el ámbito DHCP ya existe
test_dhcp_scope_exists() {
    local scope_id=$1
    grep -q "$scope_id" /etc/dhcp/dhcpd.conf
}

# Obtener detalles de la red (IP, máscara de subred, etc.)
get_network_details() {
    local server_ip=$1
    local cidr=$2

    # Llamar a la función para calcular la máscara de subred
    calcular_mascara_subred "$cidr"

    # Llamar a la función para calcular red y broadcast
    calcular_red_broadcast "$server_ip"
}
	
Add_User() {
    echo -e "\nIngrese el nombre de usuario: "
    read usuario

    if [[ -z "$usuario" ]]; then
        echo "Error: El nombre de usuario no puede estar vacío."
        return 1
    fi

    while true; do
        echo -e "\nIngrese la contraseña (mínimo 8 caracteres): "
        read -s pass  # Oculta la entrada

        if [[ -z "$pass" ]]; then
            echo "Error: La contraseña no puede estar vacía."
        elif (( ${#pass} < 8 )); then
            echo "Error: La contraseña debe tener al menos 8 caracteres."
        else
            break
        fi
    done

    # Crear el usuario con su directorio home
    sudo useradd -m -s /bin/bash "$usuario"

    if [[ $? -ne 0 ]]; then
        echo "Error: No se pudo crear el usuario."
        return 1
    fi

    # Asignar la contraseña
    echo "$usuario:$pass" | sudo chpasswd

    echo "Usuario '$usuario' creado exitosamente."
}


# Función para eliminar usuario
Delete_User() {
    local usuario_borrado

    while [[ -z "$usuario_borrado" ]]; do
        read -p "Ingrese el nombre del usuario que desea eliminar: " usuario_borrado
    done

    if id "$usuario_borrado" &>/dev/null; then
        sudo deluser --remove-home "$usuario_borrado"
        echo "Usuario eliminado con éxito."
    else
        echo "El usuario '$usuario_borrado' no existe."
    fi
}

# Función para obtener información de usuario
Info_User() {
    local info_user
    while [[ -z "$info_user" ]]; do
        read -p "Ingrese el usuario del que desea obtener información: " info_user
    done

    if id "$info_user" &>/dev/null; then
        echo "Información del usuario '$info_user':"
        getent passwd "$info_user"
    else
        echo "El usuario '$info_user' no existe."
    fi
}

