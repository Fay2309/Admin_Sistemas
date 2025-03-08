#!/bin/bash

source "/home/gael/Desktop/Scripts/Funciones.sh"

#Root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Este script debe ejecutarse como root. Usa 'sudo'."
    exit 1
fi

#Solicitar IP 
while true; do
    read -rp "Introduce la dirección IP del servidor DNS (IPv4): " DNSIP
    if validate_ipv4 "$DNSIP"; then
        break
    else
        echo "Dirección IP inválida. Introduce una dirección IPv4 válida."
    fi
done

#Dominio
read -rp "Introduce el nombre del dominio: " DomainName

# Verificar si BIND9 está instalado correctamente
if ! command -v named &> /dev/null; then
    echo "BIND9 no está instalado. Instalándolo..."
    apt update && apt install -y bind9 bind9utils
    if ! command -v named &> /dev/null; then
        echo "Error: No se pudo instalar BIND9."
        exit 1
    fi
    echo "BIND9 instalado correctamente."
else
    echo "BIND9 ya está instalado."
fi


#DNS
ZONE_FILE="/etc/bind/db.$DomainName"
ZONE_CONFIG="/etc/bind/named.conf.local"

if ! grep -q "zone \"$DomainName\"" "$ZONE_CONFIG"; then
    echo "Creando configuración de zona DNS..."
cat << EOF | sudo tee -a "$ZONE_CONFIG"
zone "$DomainName" {
    type master;
    file "/etc/bind/db.$DomainName";
    allow-query { any; };
};
EOF

#ZONA
cat << EOF > "$ZONE_FILE"
\$TTL    604800
@   IN  SOA ns.$DomainName. root.$DomainName. (
        $(date +%Y%m%d%H) ; Serial
    604800      ; Refresh
     86400      ; Retry
   2419200      ; Expire
    604800 )    ; Negative Cache TTL
@   IN  NS  ns.$DomainName.
@   IN  A   $DNSIP
ns  IN  A   $DNSIP
www IN  A   $DNSIP
EOF

    echo "Zona DNS creada correctamente en '$ZONE_FILE'."
else
    echo "La zona DNS '$DomainName' ya está configurada."
fi

# Reiniciar servicio BIND9
echo "Reiniciando el servicio BIND9..."
systemctl restart bind9

echo "El servidor DNS se configuró correctamente"
