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
    
    # Seleccionar método de descarga
    echo "Seleccione el método de descarga de Tomcat:"
    echo "1) Desde la web oficial"
    echo "2) Desde el servidor FTP"
    read -p "Ingrese el número de la opción deseada: " opcion_descarga

    if [[ "$opcion_descarga" == "1" ]]; then
        # Descargar desde la web oficial
        echo "Descargando Tomcat desde la web oficial..."
        e_descarga="https://dlcdn.apache.org/tomcat/tomcat-${tomcatV}/v${version}/bin/apache-tomcat-${version}.tar.gz"
        wget "$e_descarga" -O "/tmp/apache-tomcat-${version}.tar.gz" &>/dev/null || {
            echo "Error: No se pudo descargar Tomcat desde la web oficial."
            return 1
        }
    elif [[ "$opcion_descarga" == "2" ]]; then
        # Descargar desde el servidor FTP
        echo "Descargando Tomcat desde el servidor FTP..."
        ruta_ftp="/Servidores/Tomcat/${tomcatV}/apache-tomcat-${version}.tar.gz"
        lftp -u hola,1234 192.168.0.20 -e "
            set ssl:verify-certificate no;
            get -c ${ruta_ftp} -o /tmp/apache-tomcat-${version}.tar.gz;
            bye;
        " || {
            echo "Error: No se pudo descargar Tomcat desde el servidor FTP."
            return 1
        }
    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

    # Extraer Tomcat
    echo "Extrayendo Tomcat..."
    sudo mkdir -p "$dir_tomcat"
    sudo tar -xzf "/tmp/apache-tomcat-${version}.tar.gz" -C "$dir_tomcat" --strip-components=1 &>/dev/null
    rm "/tmp/apache-tomcat-${version}.tar.gz"

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

instalar_nginx() {
    local version="$1"
    local tipo="$2"
    local puerto="$3"
    local ruta="$4"
    local nombre_archivo_nginx="nginx-${version}.tar.gz"
    local enlace_web="https://nginx.org/download/${nombre_archivo_nginx}"
    local enlace_ftp="/Servidores/Nginx/${tipo}/${nombre_archivo_nginx}"

    echo "Seleccione el método de descarga de NGINX:"
    echo "1) Desde la web oficial"
    echo "2) Desde el servidor FTP"
    read -rp "Ingrese el número de la opción deseada: " opcion_descarga

    if [[ "$opcion_descarga" == "1" ]]; then
        # Descargar desde la web oficial
        echo "Descargando NGINX versión $version ($tipo) desde la web oficial..."
        wget "$enlace_web" -O "/tmp/${nombre_archivo_nginx}" || {
            echo "Error: No se pudo descargar NGINX desde la web oficial."
            return 1
        }
    elif [[ "$opcion_descarga" == "2" ]]; then
        # Descargar desde el servidor FTP
        echo "Descargando NGINX versión $version ($tipo) desde el servidor FTP..."
        lftp -u hola,1234 192.168.0.20 -e "
            set ssl:verify-certificate no;
            get -c ${enlace_ftp} -o /tmp/${nombre_archivo_nginx};
            bye;
        " || {
            echo "Error: No se pudo descargar NGINX desde el servidor FTP."
            return 1
        }
    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

    echo "Extrayendo archivos..."
    sudo mkdir -p "$ruta"
    sudo tar -xzf "/tmp/${nombre_archivo_nginx}" -C "$ruta" --strip-components=1 || {
        echo "Error: No se pudo extraer NGINX."
        return 1
    }

    cd "$ruta" || {
        echo "Error: No se pudo acceder al directorio de NGINX."
        return 1
    }

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

instalar_apache() {
    local version="$1"
    local puerto="$2"

    echo "Instalando Apache HTTP Server ${version} en el puerto ${puerto}..."

    # Instalar dependencias necesarias
    sudo apt update -y &>/dev/null
    sudo apt install -y build-essential libpcre3 libpcre3-dev zlib1g-dev libapr1-dev libaprutil1-dev &>/dev/null

    # Seleccionar método de descarga
    echo "Seleccione el método de descarga de Apache:"
    echo "1) Desde la web oficial"
    echo "2) Desde el servidor FTP"
    read -p "Ingrese el número de la opción deseada: " opcion_descarga

    if [[ "$opcion_descarga" == "1" ]]; then
        # Descargar desde la web oficial
        echo "Descargando Apache desde la web oficial..."
        url="https://dlcdn.apache.org/httpd/httpd-${version}.tar.gz"
        wget "$url" -O "/tmp/httpd-${version}.tar.gz" &>/dev/null || {
            echo "Error: No se pudo descargar Apache desde la web oficial."
            return 1
        }
    elif [[ "$opcion_descarga" == "2" ]]; then
        # Descargar desde el servidor FTP
        echo "Descargando Apache desde el servidor FTP..."
        ruta_ftp="/Servidores/Apache/${version}/httpd-${version}.tar.gz"
        lftp -u hola,1234 192.168.0.20 -e "
            set ssl:verify-certificate no;
            get -c ${ruta_ftp} -o /tmp/httpd-${version}.tar.gz;
            bye;
        " || {
            echo "Error: No se pudo descargar Apache desde el servidor FTP."
            return 1
        }
    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

    # Extraer y compilar Apache
    echo "Extrayendo y compilando Apache..."
    tar -xzf "/tmp/httpd-${version}.tar.gz" &>/dev/null
    cd "httpd-${version}" || return 1

    ./configure --prefix=/usr/local/apache2 --enable-so --enable-mods-shared=all &>/dev/null
    make -j$(nproc) &>/dev/null
    sudo make install &>/dev/null

    cd .. && rm -rf "httpd-${version}" "/tmp/httpd-${version}.tar.gz"

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

#---------------------------------------------------------------------------------------------------- SSL

FTPssl() {
    # Instalar vsftpd y OpenSSL
    sudo apt install vsftpd openssl -y
   
    sudo mkdir -p /srv/SSL/Linux
    sudo chmod 0755 /srv/SSL/Linux

    # Mover la carpeta de servidores dentro de /srv/SSL/Linux
    sudo mkdir -p /srv/SSL/Linux/Servidores
    sudo chown -R root:ftp /srv/SSL/Linux/Servidores
    sudo chmod -R 0770 /srv/SSL/Linux/Servidores
    
    sudo chmod g+s /srv/SSL/Linux/Servidores
   sudo setfacl -d -m g::rwx /srv/SSL/Linux/Servidores


    if [[ ! -f /etc/ssl/private/vsftpd.pem ]]; then
        sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/vsftpd.pem \
            -out /etc/ssl/private/vsftpd.pem \
            -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=FTPServer/OU=IT/CN=localhost"
    else
        echo "Certificado SSL ya existente, omitiendo generación..."
    fi

    # Configurar vsftpd
    cat <<EOF | sudo tee /etc/vsftpd.conf
listen=YES
listen_ipv6=NO

anonymous_enable=NO

local_enable=YES
write_enable=YES

max_per_ip=5

anon_other_write_enable=NO
anon_world_readable_only=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
allow_writeable_chroot=YES

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
user_sub_token=$USER
local_root=/srv/SSL/Linux/$USER

# Configuración SSL
ssl_enable=YES
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem

allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
EOF

    # Reiniciar y habilitar vsftpd
    sudo systemctl restart vsftpd

    echo "Configuración del servidor FTP con SSL completada..."
}

Crear-UsuarioFTPssl() {
    local usuario=$1

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

    # Verificar si el usuario ya existe en el sistema
    if id "$usuario" &>/dev/null; then
        echo "El usuario '$usuario' ya existe en el sistema."
        return 1
    fi
    
    sudo useradd -m -d /srv/SSL/Linux/$usuario -s /bin/bash $usuario
    sudo usermod -aG ftp $usuario  # Añadir al grupo ftp
    echo "Usuario creado, ahora configure una contraseña."
    sudo passwd $usuario

    # Asignar permisos
    sudo chown -R $usuario:ftp /srv/SSL/Linux/$usuario
    sudo chmod 0770 /srv/SSL/Linux/$usuario 

    # Montar la carpeta Servidores
    sudo mkdir -p /srv/SSL/Linux/$usuario/Servidores
    sudo mount --bind /srv/SSL/Linux/Servidores /srv/SSL/Linux/$usuario/Servidores
    sudo chmod 770 /srv/SSL/Linux/$usuario/Servidores  

    echo "Usuario '$usuario' creado correctamente con acceso a /srv/SSL/Linux/$usuario."
    sudo systemctl restart vsftpd
}

versiones_tomcatssl() {
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
        1) tomcatssl "10" "$version_lts" ;;
        2) tomcatssl "11" "$version_des" ;;
        3) return ;;
        *) echo "Opción no válida, por favor elija una opción válida..." ;;
    esac
}

tomcatssl() {
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
    local e_descarga_web="https://dlcdn.apache.org/tomcat/tomcat-${tomcatV}/v${version}/bin/apache-tomcat-${version}.tar.gz"
    local e_descarga_ftp="/Servidores/Tomcat/${tomcatV}/apache-tomcat-${version}.tar.gz"

    # Seleccionar método de descarga
    echo "Seleccione el método de descarga de Tomcat:"
    echo "1) Desde la web oficial"
    echo "2) Desde el servidor FTP"
    read -p "Ingrese el número de la opción deseada: " opcion_descarga

    if [[ "$opcion_descarga" == "1" ]]; then
        # Descargar desde la web oficial
        echo "Descargando Tomcat desde la web oficial..."
        wget "$e_descarga_web" -O "/tmp/apache-tomcat-${version}.tar.gz" &>/dev/null || {
            echo "Error: No se pudo descargar Tomcat desde la web oficial."
            return 1
        }
    elif [[ "$opcion_descarga" == "2" ]]; then
        # Descargar desde el servidor FTP
        echo "Descargando Tomcat desde el servidor FTP..."
        lftp -u hola,1234 192.168.0.20 -e "
            set ssl:verify-certificate no;
            get -c ${e_descarga_ftp} -o /tmp/apache-tomcat-${version}.tar.gz;
            bye;
        " || {
            echo "Error: No se pudo descargar Tomcat desde el servidor FTP."
            return 1
        }
    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

    # Extraer Tomcat
    echo "Extrayendo Tomcat..."
    sudo mkdir -p "$dir_tomcat"
    sudo tar -xzf "/tmp/apache-tomcat-${version}.tar.gz" -C "$dir_tomcat" --strip-components=1 &>/dev/null
    rm "/tmp/apache-tomcat-${version}.tar.gz"

    # Configurar los puertos en server.xml
    echo "Configurando Tomcat en el puerto HTTP ${puerto}..."
    sudo sed -i "s/port=\"8080\"/port=\"${puerto}\"/" "$dir_tomcat/conf/server.xml"
    sudo sed -i "s/port=\"8005\"/port=\"$((puerto + 1))\"/" "$dir_tomcat/conf/server.xml"  # Puerto de shutdown
    sudo sed -i "s/port=\"8009\"/port=\"$((puerto + 2))\"/" "$dir_tomcat/conf/server.xml"  # Puerto AJP

    # Configurar el puerto HTTPS (por ejemplo, puerto + 100)
    local puerto_https=$((puerto + 100))
    echo "Configurando Tomcat en el puerto HTTPS ${puerto_https}..."
    sudo sed -i "/<\/Service>/i\\
<Connector port=\"${puerto_https}\" protocol=\"org.apache.coyote.http11.Http11NioProtocol\" \\n\
           maxThreads=\"200\" \\n\
           SSLEnabled=\"true\"> \\n\
    <SSLHostConfig> \\n\
        <Certificate certificateKeystoreFile=\"/etc/tomcat.keystore\" \\n\
                     type=\"RSA\" \\n\
                     certificateKeystorePassword=\"MiClaveSSL\"/> \\n\
    </SSLHostConfig> \\n\
</Connector> \\n" "$dir_tomcat/conf/server.xml"

    # Configurar redirección de HTTP a HTTPS
    sudo sed -i "s/redirectPort=\"8443\"/redirectPort=\"${puerto_https}\"/" "$dir_tomcat/conf/server.xml"

    # Configurar el archivo web.xml para redirección HTTP a HTTPS
    local web_xml_path="$dir_tomcat/webapps/ROOT/WEB-INF/web.xml"
    local security_constraint='<security-constraint>\n\
    <web-resource-collection>\n\
        <web-resource-name>Protected Context</web-resource-name>\n\
        <url-pattern>/*</url-pattern>\n\
    </web-resource-collection>\n\
    <user-data-constraint>\n\
        <transport-guarantee>CONFIDENTIAL</transport-guarantee>\n\
    </user-data-constraint>\n\
</security-constraint>'

    # Crear el directorio WEB-INF si no existe
    sudo mkdir -p "$(dirname "$web_xml_path")"

    # Crear o modificar el archivo web.xml
    if [[ ! -f "$web_xml_path" ]]; then
        # Si el archivo no existe, crearlo con la configuración básica
        cat <<EOF | sudo tee "$web_xml_path" > /dev/null
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
    $security_constraint
</web-app>
EOF
    else
        # Si el archivo existe, agregar la configuración de seguridad si no está presente
        if ! grep -q "<security-constraint>" "$web_xml_path"; then
            sudo sed -i "/<\/web-app>/i $security_constraint" "$web_xml_path"
        fi
    fi

    echo "Configuración de seguridad (security-constraint) agregada en $web_xml_path."

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

    echo "Tomcat ${tomcatV} versión ${version} ha sido instalado y configurado en el puerto HTTP ${puerto} y HTTPS ${puerto_https}."
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
seleccionar_e_instalar_nginxssl() {
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

    instalar_nginxssl "$version_nginx" "$tipo_version" "$puerto" "$ruta_instalacion"
}

# Función para instalar NGINX con SSL
instalar_nginxssl() {
    local version="$1"
    local tipo="$2"
    local puerto="$3"
    local ruta="$4"
    local nombre_archivo_nginx="nginx-${version}.tar.gz"
    local enlace_web="https://nginx.org/download/${nombre_archivo_nginx}"
    local enlace_ftp="/Servidores/Nginx/${tipo}/${nombre_archivo_nginx}"

    echo "Seleccione el método de descarga de NGINX:"
    echo "1) Desde la web oficial"
    echo "2) Desde el servidor FTP"
    read -rp "Ingrese el número de la opción deseada: " opcion_descarga

    if [[ "$opcion_descarga" == "1" ]]; then
        echo "Descargando NGINX versión $version ($tipo) desde la web..."
        wget "$enlace_web" -O "/tmp/${nombre_archivo_nginx}" || { echo "Error al descargar NGINX desde la web."; return 1; }

    elif [[ "$opcion_descarga" == "2" ]]; then
echo "Descargando NGINX versión $version ($tipo) desde el FTP..."

# Eliminar archivo si existe
rm -f "/tmp/${nombre_archivo_nginx}"

# Uso de lftp con sobrescritura habilitada
lftp -u hola,1234 192.168.0.20 -e "
    set ssl:verify-certificate no;
    get -c ${enlace_ftp} -o /tmp/${nombre_archivo_nginx};
    bye;
" || { echo "Error al descargar NGINX desde el FTP."; return 1; }


    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

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

    echo "Generando certificado SSL autofirmado..."
    sudo mkdir -p "$ruta/ssl"
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$ruta/ssl/nginx-selfsigned.key" \
        -out "$ruta/ssl/nginx-selfsigned.crt" \
        -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=NGINXServer/OU=IT/CN=localhost"

    echo "Configurando NGINX para usar SSL y redirigir HTTP a HTTPS..."
    sudo bash -c "cat > $ruta/conf/nginx.conf" <<EOF
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;

    sendfile        on;
    keepalive_timeout  65;

    # Configuración del servidor HTTP (redirige a HTTPS)
    server {
        listen ${puerto};
        server_name localhost;

        # Redirigir todo el tráfico HTTP a HTTPS
        return 301 https://\$host:$(($puerto + 1));
    }

    # Configuración del servidor HTTPS
    server {
        listen $(($puerto + 1)) ssl;
        server_name localhost;

        ssl_certificate $ruta/ssl/nginx-selfsigned.crt;
        ssl_certificate_key $ruta/ssl/nginx-selfsigned.key;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            root   html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }
    }
}
EOF

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

    sudo systemctl daemon-reload
    sudo systemctl enable "$servicio_nombre"
    sudo systemctl start "$servicio_nombre"
    sudo systemctl restart "$servicio_nombre"

    echo "NGINX versión $version ($tipo) ha sido instalado y configurado en el puerto HTTP ${puerto} y HTTPS $(($puerto + 1))."
}

# Función para seleccionar la versión de Apache
seleccionar_e_instalar_apachessl() {
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

    instalar_apachessl "$version_apache" "$puerto"
}

instalar_apachessl() {
    local version="$1"
    local puerto_https="$2"  # Ahora solo se usa el puerto HTTPS

    echo "Instalando Apache HTTP Server ${version} en el puerto HTTPS ${puerto_https}..."

    # Instalar dependencias necesarias
    sudo apt update -y &>/dev/null
    sudo apt install -y build-essential libpcre3 libpcre3-dev zlib1g-dev libapr1-dev libaprutil1-dev libssl-dev &>/dev/null

    # Seleccionar método de descarga
    echo "Seleccione el método de descarga de Apache:"
    echo "1) Desde la web oficial"
    echo "2) Desde el servidor FTP"
    read -p "Ingrese el número de la opción deseada: " opcion_descarga

    if [[ "$opcion_descarga" == "1" ]]; then
        # Descargar desde la web oficial
        echo "Descargando Apache desde la web oficial..."
        url="https://dlcdn.apache.org/httpd/httpd-${version}.tar.gz"
        wget "$url" -O "httpd-${version}.tar.gz" &>/dev/null || {
            echo "Error: No se pudo descargar Apache desde la web oficial."
            return 1
        }
    elif [[ "$opcion_descarga" == "2" ]]; then
        # Descargar desde el servidor FTP
        echo "Descargando Apache desde el servidor FTP..."
        ruta_ftp="/Servidores/Apache/${version}/httpd-${version}.tar.gz"
        lftp -u hola,1234 192.168.0.20 -e "
            set ssl:verify-certificate no;
            get -c ${ruta_ftp} -o httpd-${version}.tar.gz;
            bye;
        " || {
            echo "Error: No se pudo descargar Apache desde el servidor FTP."
            return 1
        }
    else
        echo "Opción no válida. Saliendo..."
        return 1
    fi

    # Extraer y compilar Apache
    echo "Extrayendo y compilando Apache..."
    tar -xzf "httpd-${version}.tar.gz" &>/dev/null
    cd "httpd-${version}" || return 1

    ./configure --prefix=/usr/local/apache2 --enable-so --enable-ssl --enable-mods-shared=all &>/dev/null
    make -j$(nproc) &>/dev/null
    sudo make install &>/dev/null

    cd .. && rm -rf "httpd-${version}" "httpd-${version}.tar.gz"

    # Verificar que la instalación se completó
    if [ ! -f "/usr/local/apache2/conf/httpd.conf" ]; then
        echo "Error: No se encontró el archivo de configuración /usr/local/apache2/conf/httpd.conf"
        return 1
    fi

    # Configurar el puerto HTTPS
    sudo sed -i "s/^Listen .*/Listen ${puerto_https}/" /usr/local/apache2/conf/httpd.conf

    # Generar un certificado autofirmado
    echo "Generando certificado SSL autofirmado..."
    sudo mkdir -p /usr/local/apache2/conf/ssl
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /usr/local/apache2/conf/ssl/apache-selfsigned.key \
        -out /usr/local/apache2/conf/ssl/apache-selfsigned.crt \
        -subj "/C=MX/ST=Sinaloa/L=Culiacan/O=ApacheServer/OU=IT/CN=localhost" &>/dev/null

    # Configurar Virtual Host para HTTPS
    cat <<EOF | sudo tee /usr/local/apache2/conf/extra/httpd-ssl.conf > /dev/null
<VirtualHost *:${puerto_https}>
    SSLEngine on
    SSLCertificateFile /usr/local/apache2/conf/ssl/apache-selfsigned.crt
    SSLCertificateKeyFile /usr/local/apache2/conf/ssl/apache-selfsigned.key

    DocumentRoot "/usr/local/apache2/htdocs"
    <Directory "/usr/local/apache2/htdocs">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

    # Habilitar el módulo SSL y el Virtual Host SSL
    if ! grep -q "^LoadModule ssl_module" /usr/local/apache2/conf/httpd.conf; then
        echo "LoadModule ssl_module modules/mod_ssl.so" | sudo tee -a /usr/local/apache2/conf/httpd.conf > /dev/null
    fi
    if ! grep -q "^Include conf/extra/httpd-ssl.conf" /usr/local/apache2/conf/httpd.conf; then
        echo "Include conf/extra/httpd-ssl.conf" | sudo tee -a /usr/local/apache2/conf/httpd.conf > /dev/null
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

    echo "Apache HTTP Server ${version} ha sido instalado y configurado en el puerto HTTPS ${puerto_https}."
}

instalar_servicios() {
    echo "Actualizando paquetes del sistema..."
    sudo apt update
    
    echo "Instalando Postfix (SMTP), Dovecot (POP3) y Apache..."
    sudo apt-get install -y postfix dovecot-pop3d dovecot-imapd

    echo "Instalación completada."
}

configurar_dominio_postfix() {
    local dominio="gael"

    echo "Configurando el dominio $dominio en Postfix..."

    # Agregar el dominio a mydestination en main.cf si no está presente
    if ! grep -q "^mydestination.*$dominio" /etc/postfix/main.cf; then
        sudo sed -i "/^mydestination =/ s/$/, $dominio/" /etc/postfix/main.cf
        echo "Dominio $dominio agregado a mydestination."
    else
        echo "El dominio $dominio ya está en mydestination."
    fi

    # Agregar el dominio a transport si no está presente
    if ! grep -q "^$dominio" /etc/postfix/transport; then
        echo "$dominio smtp:[127.0.0.1]" | sudo tee -a /etc/postfix/transport > /dev/null
        sudo postmap /etc/postfix/transport
        echo "Regla de transporte agregada para $dominio."
    else
        echo "El dominio $dominio ya está en transport."
    fi

    # Reiniciar Postfix para aplicar cambios
    sudo systemctl restart postfix
    echo "Postfix ha sido recargado con la nueva configuración."
    
    echo $dominio
}

instalar_squirrelmail() {
    local dominio="$1"
    echo "Descargando e instalando SquirrelMail..."
    
    sudo apt install software-properties-common -y
    sudo add-apt-repository ppa:ondrej/php -y
    sudo apt update
    sudo apt install php7.4 libapache2-mod-php7.4 php-mysql -y
    
    data_directory="/var/www/html/squirrelmail/data/"
    attach_directory="/var/www/html/squirrelmail/attach/"
    
    install_dir="/var/www/html/squirrelmail"
    
    cd /var/www/html
    sudo wget -O squirrelmail.zip "https://sourceforge.net/projects/squirrelmail/files/stable/1.4.22/squirrelmail-webmail-1.4.22.zip/download" -q 
    
    unzip -q squirrelmail.zip
    sudo mv squirrelmail-webmail-1.4.22 squirrelmail
    rm squirrelmail.zip
    
    sudo chown -R www-data:www-data "$install_dir/"
    sudo chmod -R 755 "$install_dir/"
    
    config_file="$install_dir/config/config_default.php"
    
    sudo sed -i "s/^\$domain.*/\$domain = '$dominio';/" "$config_file"
    sudo sed -i "s|^\$data_dir.*| \$data_dir = '$data_directory';|" "$config_file"
    sudo sed -i "s|^\$attachment_dir.*| \$attachment_dir = '$attach_directory';|" "$config_file"
    sudo sed -i "s/^\$allow_server_sort.*/\$allow_server_sort = true;/" "$config_file"
    
    echo -e "s\n\nq" | sudo perl "$install_dir/config/conf.pl"
    
    sudo systemctl reload apache2
    sudo systemctl restart apache2
    
    echo "Squirrelmail esta listo... Acceso mediante http://$dominio"
}

crear_usuarios_mailbox() {
    for usuario in chabelo pepito; do
        # Verificar si el usuario ya existe
        if id "$usuario" &>/dev/null; then
            echo "El usuario $usuario ya existe."
        else
            # Crear el usuario sin shell de acceso y con directorio home
            sudo useradd -m -s /bin/false "$usuario"
            echo "$usuario:password" | sudo chpasswd
            echo "Usuario $usuario creado con contraseña predeterminada."
        fi

        # Crear el buzón de correo en /var/mail/
        mailbox="/var/mail/$usuario"
        if [ ! -f "$mailbox" ]; then
            sudo touch "$mailbox"
            sudo chown "$usuario":mail "$mailbox"
            sudo chmod 644 "$mailbox"
            echo "Buzón de correo creado para $usuario."
        else
            echo "El buzón de correo para $usuario ya existe."
        fi
    done

   # El error: Falló el envío del mensaje.
   #Hubo un error mientras se enviaba el correo: El servidor de correo respondió:  
   #<envio@gael.com>: Relay access denied.
   #Revisa el destinatario "envio@gael.com" e inténtalo de nuevo.
   #Se arregla entrando a: nano /etc/postfix/main.cf 
   # Buscar la línea mydestination =  - y colocar el dominio que se está colocando en Thunderbird 
}

verificar_servicios() {
    echo "Verificando servicios..."
    echo -e "\nEstado de Postfix:"
    sudo systemctl status postfix | grep "Active:"
    
    echo -e "\nEstado de Dovecot:"
    sudo systemctl status dovecot | grep "Active:"
    
    echo -e "\nPuertos escuchando:"
    sudo netstat -tulnp | grep -E 'postfix|dovecot'
}

mostrar_info() {
    echo ""
    echo "============================================"
    echo "Configuración completada"
    echo "============================================"
    echo "Servidor SMTP (Postfix):"
    echo "  Dirección: $(hostname)"
    echo "  Puerto: 25"
    echo "  Autenticación: PLAIN/LOGIN"
    echo ""
    echo "Servidor POP3 (Dovecot):"
    echo "  Dirección: $(hostname)"
    echo "  Puerto: 110"
    echo ""
    echo "SquirrelMail:"
    echo "  URL de acceso: http://$(hostname)/squirrelmail"
    echo ""
    echo "Configuración para clientes:"
    echo "  Thunderbird/SquirrelMail:"
    echo "    SMTP: $(hostname), puerto 25, sin SSL"
    echo "    POP3: $(hostname), puerto 110, sin SSL"
    echo "    Autenticación: Normal password"
    echo "============================================"
    echo ""
}
