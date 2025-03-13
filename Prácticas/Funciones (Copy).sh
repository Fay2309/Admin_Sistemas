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

#---------------------------------------------------------------------------------- HTTP 

validar_puerto() {
    local puerto="$1"
    local reserved_ports=(21 22 23 25 53 110 119 123 135 137 138 139 143 161 162 389 443 445 465 587 636 993 995 1433 1521 1723 3306 3389 5900 8443 27017 5432)

    # Verificar si es un número y está en el rango permitido
    if ! [[ "$puerto" =~ ^[0-9]+$ ]] || ((puerto < 1 || puerto > 65535)); then
        echo "Error: El puerto debe ser un número entre 1 y 65535."
        return 1
    fi

    # Verificar si está en la lista de puertos reservados
    for p in "${reserved_ports[@]}"; do
        if [[ "$puerto" -eq "$p" ]]; then
            echo "Error: El puerto $puerto está reservado y no se puede usar."
            return 1
        fi
    done

    # Verificar si el puerto está en uso
    if sudo lsof -i :"$puerto" &>/dev/null; then
        echo "Error: El puerto $puerto ya está en uso. Por favor, elija otro."
        return 1
    fi

    return 0
}

versiones_tomcat() {
    local url_lts="https://tomcat.apache.org/download-10.cgi"
    local url_des="https://tomcat.apache.org/download-11.cgi"

    # Obtener el HTML de las páginas de descarga
    local html_lts=$(curl -s "$url_lts")
    local html_des=$(curl -s "$url_des")

    # Extraer versión de Tomcat 10 (LTS)
    local version_lts=$(echo "$html_lts" | grep -oP 'apache-tomcat-\K[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)

    # Extraer versión de Tomcat 11 (Desarrollo)
    local version_des=$(echo "$html_des" | grep -oP 'apache-tomcat-\K[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)

    # Validar que se hayan obtenido las versiones
    if [[ -z "$version_lts" || -z "$version_des" ]]; then
        echo "Error: No se pudo obtener la versión de Tomcat. Revisa la página de Apache."
        return 1
    fi

    echo "Seleccione la versión de Tomcat:"
    echo "1.- Tomcat 10 (LTS) - Versión: $version_lts"
    echo "2.- Tomcat 11 (Desarrollo) - Versión: $version_des"
    echo "3.- Volver"

    read -p "Seleccione una opción (1-3): " opcion
    case "$opcion" in
        1) tomcat "10" "$version_lts" ;;
        2) tomcat "11" "$version_des" ;;
        3) return ;;
        *) echo "Opción no válida, por favor elija una opción válida..." ;;
    esac
}

tomcat() {
    local tomcatV="$1"
    local version="$2"
    local reserved_ports=(21 22 23 25 53 110 119 123 135 137 138 139 143 161 162 389 443 445 465 587 636 993 995 1433 1521 1723 3306 3389 5900 8443 27017 5432)
    local puerto

    while true; do
        read -p "Ingrese el puerto en el que desea configurar Tomcat: " puerto

        # Validar que el puerto sea un número entero
        if ! [[ "$puerto" =~ ^[0-9]+$ ]]; then
            echo "Error: El puerto debe ser un número entero."
            continue
        fi

        # Validar que esté en el rango válido (1-65535)
        if (( puerto < 1 || puerto > 65535 )); then
            echo "Error: El puerto debe estar entre 1 y 65535."
            continue
        fi

        # Validar que el puerto no esté en la lista de puertos reservados
        if [[ " ${reserved_ports[@]} " =~ " $puerto " ]]; then
            echo "Error: El puerto $puerto está reservado para otro servicio. Elija otro."
            continue
        fi

        # Verificar si el puerto está en uso
        if sudo lsof -i :$puerto &>/dev/null; then
            echo "Error: El puerto $puerto ya está en uso. Por favor, elija otro."
            continue
        fi

        # Si pasa todas las validaciones, salir del bucle
        break
    done

    echo "Tomcat ${tomcatV} versión ${version} está siendo instalado en el puerto ${puerto}..."

    # Verificar si Java está instalado
    if ! command -v java &>/dev/null; then
        echo "Java no está instalado, instalando OpenJDK 17..."
        sudo apt-get update -y &>/dev/null
        sudo apt-get install -y openjdk-17-jdk &>/dev/null
    fi

    # Definir carpeta específica para la versión
    local dir_tomcat="/opt/tomcat${tomcatV}"
    
    # Obtener enlace de descarga
    local e_descarga="https://dlcdn.apache.org/tomcat/tomcat-${tomcatV}/v${version}/bin/apache-tomcat-${version}.tar.gz"

    # Verificar si la URL es accesible
    if ! curl --output /dev/null --silent --head --fail "$e_descarga"; then
        echo "Error: No se pudo obtener el enlace de descarga de Tomcat. URL inválida: $e_descarga"
        return 1
    fi

    # Descargar y extraer Tomcat en un directorio separado
    echo "Descargando Tomcat desde: ${e_descarga}"
    local a_tomcat=$(basename "$e_descarga")
    wget "$e_descarga" -O "$a_tomcat" &>/dev/null
    sudo mkdir -p "$dir_tomcat"
    sudo tar -xzf "$a_tomcat" -C "$dir_tomcat" --strip-components=1 &>/dev/null
    rm "$a_tomcat"

    # Configurar los puertos en server.xml
    echo "Configurando Tomcat en el puerto ${puerto}..."
    sudo sed -i "s/port=\"8080\"/port=\"${puerto}\"/" "$dir_tomcat/conf/server.xml"
    sudo sed -i "s/port=\"8005\"/port=\"$((puerto + 1))\"/" "$dir_tomcat/conf/server.xml"  # Puerto de shutdown
    sudo sed -i "s/port=\"8009\"/port=\"$((puerto + 2))\"/" "$dir_tomcat/conf/server.xml"  # Puerto AJP

    # Crear servicio systemd para cada instancia
    local service_name="tomcat${tomcatV}"
    cat <<EOF | sudo tee /etc/systemd/system/${service_name}.service > /dev/null
[Unit]
Description=Apache Tomcat ${tomcatV} Web Application Server
After=network.target

[Service]
Type=forking
Environment="JAVA_HOME=$(readlink -f /usr/bin/java | sed 's|/bin/java||')"
Environment="CATALINA_PID=${dir_tomcat}/temp/tomcat.pid"
Environment="CATALINA_HOME=${dir_tomcat}"
Environment="CATALINA_BASE=${dir_tomcat}"
Environment="JAVA_OPTS=-Djava.security.egd=file:/dev/./urandom"
ExecStart=${dir_tomcat}/bin/catalina.sh start
ExecStop=${dir_tomcat}/bin/catalina.sh stop
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Iniciar y habilitar Tomcat
    sudo systemctl daemon-reload
    sudo systemctl enable ${service_name}
    sudo systemctl start ${service_name}
    sudo systemctl restart ${service_name}

    echo "Tomcat ${tomcatV} versión ${version} ha sido instalado y configurado en el puerto ${puerto}."
}


# Función para obtener la versión Mainline de Nginx
obtener_version_nginx_mainline() {
    curl -s https://nginx.org/en/download.html | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -n1
}

# Función para obtener la versión Stable de Nginx
obtener_version_nginx_stable() {
    ng_page=$(curl -s https://nginx.org/en/download.html)
    version_lts=$(echo "$ng_page" | grep -oP '(?<=Stable version</h4>).*?nginx-\K\d+\.\d+\.\d+' | head -1)
    echo "$version_lts"
}

# Función para seleccionar e instalar NGINX
seleccionar_e_instalar_nginx() {
    echo "Seleccione la versión de Nginx a instalar:"
    echo "1) Mainline (Última versión en desarrollo)"
    echo "2) Stable (Última versión estable)"
    read -rp "Ingrese el número de la opción deseada: " opcion_version

    if [[ "$opcion_version" == "1" ]]; then
        version_nginx=$(obtener_version_nginx_mainline)
        tipo_version="Mainline"
        ruta_instalacion="/usr/local/nginx-mainline"
    elif [[ "$opcion_version" == "2" ]]; then
        version_nginx=$(obtener_version_nginx_stable)
        tipo_version="Stable"
        ruta_instalacion="/usr/local/nginx-stable"
    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

    while true; do
        read -rp "Ingrese el puerto en el que desea ejecutar Nginx: " puerto
        if validar_puerto "$puerto"; then
            break
        fi
    done

    instalar_nginx "$version_nginx" "$tipo_version" "$puerto" "$ruta_instalacion"
}

# Función para instalar NGINX
instalar_nginx() {
    local version="$1"
    local tipo="$2"
    local puerto="$3"
    local ruta="$4"
    local nombre_archivo_nginx="nginx-${version}.tar.gz"
    local enlace_descarga="https://nginx.org/download/${nombre_archivo_nginx}"

    echo "Descargando NGINX versión $version ($tipo) desde $enlace_descarga..."
    wget "$enlace_descarga" -O "/tmp/${nombre_archivo_nginx}" || { echo "Error al descargar NGINX."; return 1; }

    echo "Extrayendo archivos..."
    sudo mkdir -p "$ruta"
    sudo tar -xzf "/tmp/${nombre_archivo_nginx}" -C "$ruta" --strip-components=1 || { echo "Error al extraer NGINX."; return 1; }

    cd "$ruta" || { echo "Error al acceder al directorio de NGINX."; return 1; }

    echo "Instalando dependencias necesarias..."
    sudo apt-get update -y
    sudo apt-get install -y build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev

    echo "Configurando y compilando NGINX..."
    sudo ./configure --prefix="$ruta" --with-http_ssl_module --with-pcre
    sudo make -j$(nproc)
    sudo make install

    echo "Configurando NGINX en el puerto ${puerto}..."
    sudo sed -i "s/listen[[:space:]]*80;/listen ${puerto};/g" "$ruta/conf/nginx.conf"

    echo "Creando directorios de logs si no existen..."
    sudo mkdir -p "$ruta/logs"
    sudo touch "$ruta/logs/error.log" "$ruta/logs/nginx.pid"
    sudo chmod 777 "$ruta/logs/error.log" "$ruta/logs/nginx.pid"

    echo "Creando servicio systemd para NGINX (${tipo})..."
    local servicio_nombre="nginx-${tipo,,}.service"
    sudo bash -c "cat > /etc/systemd/system/${servicio_nombre}" <<EOF
[Unit]
Description=NGINX $tipo
After=network.target

[Service]
Type=forking
PIDFile=$ruta/logs/nginx.pid
ExecStartPre=$ruta/sbin/nginx -t
ExecStart=$ruta/sbin/nginx
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s TERM \$MAINPID

[Install]
WantedBy=multi-user.target
EOF

    echo "Habilitando y arrancando NGINX ($tipo)..."
    sudo systemctl daemon-reload
    sudo systemctl enable "$servicio_nombre"
    sudo systemctl start "$servicio_nombre"
    sudo systemctl restart "$servicio_nombre"

    echo "NGINX versión $version ($tipo) ha sido instalado y configurado en el puerto ${puerto}."
}

# Función para seleccionar la versión de Apache
seleccionar_e_instalar_apache() {
    while true; do
        echo "Seleccione la versión de Apache a instalar:"
        echo "1) LTS"
        echo "2) Desarrollo"
        read -rp "Ingrese el número de la opción deseada: " opcion_version

        if [[ "$opcion_version" == "1" ]]; then
            version_apache="2.4.63"
            break
        elif [[ "$opcion_version" == "2" ]]; then
            echo "EASTER EGG: Esta no existe profe, haga paro :D"
        else
            echo "Opción no válida. Intente de nuevo."
        fi
    done

    while true; do
        read -rp "Ingrese el puerto en el que desea configurar Apache: " puerto
        if validar_puerto "$puerto"; then
            break
        fi
    done

    instalar_apache "$version_apache" "$puerto"
}

# Función para instalar Apache
instalar_apache() {
    local version="$1"
    local puerto="$2"
    local url="https://dlcdn.apache.org/httpd/httpd-${version}.tar.gz"

    echo "Instalando Apache HTTP Server ${version} en el puerto ${puerto}..."

    # Instalar dependencias necesarias
    sudo apt update -y &>/dev/null
    sudo apt install -y build-essential libpcre3 libpcre3-dev zlib1g-dev libapr1-dev libaprutil1-dev &>/dev/null

    # Descargar Apache
    wget "$url" -O "httpd-${version}.tar.gz" &>/dev/null

    # Extraer y compilar Apache
    tar -xzf "httpd-${version}.tar.gz" &>/dev/null
    cd "httpd-${version}" || return 1

    ./configure --prefix=/usr/local/apache2 --enable-so --enable-mods-shared=all &>/dev/null
    make -j$(nproc) &>/dev/null
    sudo make install &>/dev/null

    cd .. && rm -rf "httpd-${version}" "httpd-${version}.tar.gz"

    # Verificar que la instalación se completó
    if [ ! -f "/usr/local/apache2/conf/httpd.conf" ]; then
        echo "Error: No se encontró el archivo de configuración /usr/local/apache2/conf/httpd.conf"
        return 1
    fi

    # Configurar el puerto
    if grep -q "^Listen " /usr/local/apache2/conf/httpd.conf; then
        sudo sed -i "s/^Listen [0-9]\+/Listen ${puerto}/" /usr/local/apache2/conf/httpd.conf
    else
        echo "Listen ${puerto}" | sudo tee -a /usr/local/apache2/conf/httpd.conf > /dev/null
    fi

    # Crear servicio systemd para Apache
    cat <<EOF | sudo tee /etc/systemd/system/apache.service &>/dev/null
[Unit]
Description=Apache HTTP Server
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/apache2/bin/apachectl start
ExecStop=/usr/local/apache2/bin/apachectl stop
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Iniciar y habilitar Apache
    sudo systemctl daemon-reload &>/dev/null
    sudo systemctl enable apache &>/dev/null
    sudo systemctl start apache &>/dev/null
    sudo systemctl restart apache &>/dev/null

    echo "Apache HTTP Server ${version} ha sido instalado y configurado en el puerto ${puerto}."
}
