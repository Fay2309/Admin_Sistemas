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

#---------------------------------------FTP
FTP() {
    # Instalar vsftpd
    sudo apt install vsftpd -y

    # Crear grupos
    sudo groupadd reprobados
    sudo groupadd recursadores

    sudo mkdir -p /srv/FTP/LocalUser
    sudo mkdir -p /srv/FTP/LocalUser/Public
    sudo mkdir -p /srv/FTP/reprobados
    sudo mkdir -p /srv/FTP/recursadores
    sudo mkdir -p /srv/FTP//LocalUser/anon-public
    sudo mkdir -p /srv/FTP/LocalUser/anon-public/Public	

    # Permisos y propietarios
    sudo chmod 0755 /srv/FTP/LocalUser/Public
    
    sudo chown root:reprobados /srv/FTP/reprobados
    sudo chmod 0770 /srv/FTP/reprobados
    
    sudo chown root:recursadores /srv/FTP/recursadores
    sudo chmod 0770 /srv/FTP/recursadores
    
    sudo chmod 0755 /srv/FTP
    
    sudo chmod 0555 /srv/FTP//LocalUser/anon-public 
    sudo chown root: /srv/FTP//LocalUser/anon-public

    sudo mount --bind /srv/FTP/LocalUser/Public /srv/FTP/LocalUser/anon-public/Public
    sudo chmod 0555 /srv/FTP/LocalUser/anon-public/Public  

    # Configurar vsftpd
    cat <<EOF | sudo tee /etc/vsftpd.conf
listen=YES
listen_ipv6=NO

anonymous_enable=YES

local_enable=YES
write_enable=YES

dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
anon_root=/srv/FTP/LocalUser/anon-public


chroot_local_user=YES
allow_writeable_chroot=YES
EOF

    # Reiniciar y habilitar vsftpd
    sudo systemctl restart vsftpd

    echo "Configuración del servidor FTP completada..."
}

Eliminar-UsuarioFTP() {
    local usuario="$1"
    local rutaUsuario="/srv/FTP/LocalUser/$usuario"

    # Verificar si el usuario existe en el sistema
    if ! id "$usuario" &>/dev/null; then
        echo "El usuario '$usuario' no existe en el sistema."
        return 1
    fi

    # Terminar procesos activos del usuario
    if pgrep -u "$usuario" &>/dev/null; then
        echo "Matando procesos activos del usuario '$usuario'..."
        sudo pkill -u "$usuario"
    fi

    # Esperar a que los procesos terminen
    sleep 2

    # Dar permisos temporales para desmontar
    echo "Ajustando permisos para desmontar las carpetas..."
    sudo chmod -R 755 "$rutaUsuario"

    # Desmontar carpetas montadas antes de eliminarlas
    for carpeta in "$rutaUsuario/Public" "$rutaUsuario/reprobados" "$rutaUsuario/recursadores"; do
        if mountpoint -q "$carpeta"; then
            echo "Desmontando $carpeta..."
            sudo umount "$carpeta"
        fi
    done

    # Verificar que ya no están montadas antes de proceder
    sleep 1
    for carpeta in "$rutaUsuario/Public" "$rutaUsuario/reprobados" "$rutaUsuario/recursadores"; do
        if mountpoint -q "$carpeta"; then
            echo "Error: No se pudo desmontar $carpeta. Intente nuevamente."
            return 1
        fi
    done

    # Eliminar la carpeta del usuario
    if [[ -d "$rutaUsuario" ]]; then
        echo "Eliminando carpeta del usuario '$rutaUsuario'..."
        sudo rm -rf "$rutaUsuario"
        echo "Se eliminó la carpeta de usuario '$rutaUsuario'."
    fi

    # Eliminar al usuario del sistema correctamente
    echo "Eliminando usuario '$usuario' del sistema..."
    sudo userdel -r "$usuario" 2>/dev/null

    # Verificar si el usuario fue eliminado
    if id "$usuario" &>/dev/null; then
        echo "Error: No se pudo eliminar completamente el usuario '$usuario'."
        return 1
    else
        echo "Usuario '$usuario' eliminado correctamente."
    fi
        sudo systemctl restart vsftpd
}

Crear-UsuarioFTP() {
    local usuario=$1
    local grupo=""

    # Validar nombre de usuario
    if [[ ! "$usuario" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "El nombre de usuario solo puede contener letras, números, guiones y guiones bajos. Intente de nuevo..."
        return 1
    fi
    
    if [[ ${#usuario} -lt 4 ]]; then
    	echo "El nombre de usuario debe tener al menos 4 caracteres. Intente de nuevo..."
    	return 1
    fi

    if [[ "$usuario" =~ ^[0-9] ]]; then
        echo "El nombre de usuario no puede comenzar con un número. Intente de nuevo..."
        return 1
    fi
    
    if [[ ${#usuario} -gt 20 ]]; then
        echo "El nombre de usuario no puede tener más de 20 caracteres. Intente de nuevo..."
        return 1
    fi

    # Seleccionar grupo
    while true; do
        echo "Seleccione el grupo para el usuario $usuario:"
        echo "1) Reprobados"
        echo "2) Recursadores"
        read -p "Ingrese el número del grupo: " opcion

        case $opcion in
            1) grupo="reprobados"; break ;;
            2) grupo="recursadores"; break ;;
            *) echo "Opción no válida. Por favor, ingrese 1 o 2." ;;
        esac
    done

    # Verificar si el usuario ya existe en el sistema
    if id "$usuario" &>/dev/null; then
        echo "El usuario '$usuario' ya existe en el sistema."
        return 1
    fi

    # Verificar si la carpeta del usuario aún existe (caso de eliminación incorrecta)
    if [[ -d "/srv/FTP/LocalUser/$usuario" ]]; then
        echo "El usuario '$usuario' no está en el sistema, pero su carpeta sigue existiendo. Eliminándola..."
        sudo rm -rf "/srv/FTP/LocalUser/$usuario"
    fi

    # Crear usuario en el sistema
    sudo useradd -m -d /srv/FTP/LocalUser/$usuario -s /bin/bash -G $grupo $usuario
    sudo passwd $usuario

    # Crear estructura de directorios
    sudo mkdir -p /srv/FTP/LocalUser/$usuario
    sudo mkdir -p /srv/FTP/LocalUser/$usuario/Public
    sudo mkdir -p /srv/FTP/LocalUser/$usuario/$grupo
    sudo mkdir -p /srv/FTP/LocalUser/$usuario/$usuario

    # Asignar permisos
    sudo chown -R $usuario:$usuario /srv/FTP/LocalUser/$usuario
    sudo chmod 700 /srv/FTP/LocalUser/$usuario

    # Montar carpetas compartidas
    mount --bind /srv/FTP/$grupo /srv/FTP/LocalUser/$usuario/$grupo
    sudo chown -R $usuario:$usuario /srv/FTP/LocalUser/$grupo
    sudo chmod 775 /srv/FTP/LocalUser/$usuario/$grupo
    #echo "/srv/FTP/$grupo /srv/FTP/LocalUser/$usuario/$grupo none bind 0 0" | sudo tee -a /etc/fstab

    mount --bind /srv/FTP/LocalUser/Public /srv/FTP/LocalUser/$usuario/Public
    sudo chown -R $usuario:$usuario /srv/FTP/LocalUser/$usuario/Public
    sudo chmod 777 /srv/FTP/LocalUser/$usuario/Public
    #echo "/srv/FTP/LocalUser/Public /srv/FTP/LocalUser/$usuario/Public none bind 0 0" | sudo tee -a /etc/fstab

    echo "Usuario '$usuario' creado correctamente en el grupo '$grupo'."
	sudo systemctl restart vsftpd
}

Cambiar-GrupoFTP() {
    local usuario="$1"

    echo "Seleccione el grupo al que reasignará al usuario $usuario"
    echo "1) Reprobados"
    echo "2) Recursadores"
    read -p "Ingrese la opción: " opcion

    case "$opcion" in
        1) nuevoGrupo="reprobados"; anteriorGrupo="recursadores" ;;
        2) nuevoGrupo="recursadores"; anteriorGrupo="reprobados" ;;
        *) echo "Opción inválida."; return 1 ;;
    esac

    echo "Cambiando a $nuevoGrupo..."

    # Dar permisos temporales para cambiar la carpeta
    echo "Ajustando permisos para mover las carpetas..."
    sudo chmod -R 755 "/srv/FTP/LocalUser/$usuario/$anteriorGrupo" 2>/dev/null
    sudo chmod -R 755 "/srv/FTP/LocalUser/$usuario/$nuevoGrupo" 2>/dev/null

    # Desmontar carpetas si están montadas
    for carpeta in "/srv/FTP/LocalUser/$usuario/$anteriorGrupo" "/srv/FTP/LocalUser/$usuario/$nuevoGrupo"; do
        if mountpoint -q "$carpeta"; then
            echo "Desmontando $carpeta..."
            sudo umount "$carpeta"
        fi
    done

    # Mover la carpeta del grupo anterior al nuevo grupo
    echo "Moviendo la carpeta del grupo '$anteriorGrupo' a '$nuevoGrupo'..."
    sudo rm -rf "/srv/FTP/LocalUser/$usuario/$nuevoGrupo"
    sudo mv "/srv/FTP/LocalUser/$usuario/$anteriorGrupo" "/srv/FTP/LocalUser/$usuario/$nuevoGrupo"

    # Ajustar propietario y permisos
    sudo chown -R "$usuario:$nuevoGrupo" "/srv/FTP/LocalUser/$usuario/$nuevoGrupo"
    sudo chmod -R 755 "/srv/FTP/LocalUser/$usuario/$nuevoGrupo"

    # Crear enlace simbólico del nuevo grupo
    sudo mount --bind "/srv/FTP/$nuevoGrupo" "/srv/FTP/LocalUser/$usuario/$nuevoGrupo"
    echo "/srv/FTP/$nuevoGrupo /srv/FTP/LocalUser/$usuario/$nuevoGrupo none bind 0 0" | sudo tee -a /etc/fstab

    # Remover el usuario del grupo anterior y agregar al nuevo
    echo "Actualizando grupos del usuario..."
    sudo gpasswd -d "$usuario" "$anteriorGrupo" 2>/dev/null
    sudo usermod -aG "$nuevoGrupo" "$usuario"

    echo "Grupo del usuario '$usuario' cambiado a '$nuevoGrupo'."
        sudo systemctl restart vsftpd
}

