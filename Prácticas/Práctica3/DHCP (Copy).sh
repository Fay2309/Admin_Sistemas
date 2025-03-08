#!/bin/bash

source "/home/gael/Desktop/Scripts/Funciones.sh"

# Entrada de datos
server_ip=$(get_valid_ip "Introduce la dirección IP del servidor DHCP")
while true; do
    start_range=$(get_valid_ip "Introduce la dirección IP de inicio del rango")
    end_range=$(get_valid_ip "Introduce la dirección IP de fin del rango")
    if [[ "$start_range" > "$end_range" ]]; then
        echo "Error: La IP final no puede ser menor que la inicial."
    else
        break
    fi
done

# Obtener detalles de la red
get_network_details "$server_ip" 24

sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bak

# Configurar interfaz en Netplan
cat <<EOF | sudo tee /etc/netplan/50-cloud-init.yaml
network:
  version: 2
  ethernets:
    ens38:
      dhcp4: true
    ens37:
      dhcp4: false
      addresses:
        - $server_ip/24
      gateway4: $server_ip
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
EOF

sudo netplan apply

# Verificar si el ámbito ya existe
if test_dhcp_scope_exists "$server_ip"; then
    echo "Error: Ya existe un ámbito DHCP con la misma dirección IP del servidor ($server_ip)."
    exit 1
fi

# Configuración del archivo DHCP
cat <<EOF | sudo tee /etc/dhcp/dhcpd.conf
subnet $network_ip netmask $subnet_mask {
    range $start_range $end_range;
    option routers $server_ip;
    option broadcast-address $broadcast_ip;
    option subnet-mask $subnet_mask
    option domain-name-servers 8.8.8.8, 8.8.4.4;
    default-lease-time 600;
    max-lease-time 7200;
}
EOF

# Reiniciar servicio DHCP
echo "Reiniciando el servicio DHCP..."
sudo systemctl restart isc-dhcp-server
sudo systemctl enable isc-dhcp-server

# Resumen de la configuración
echo "Configuración del servidor DHCP completada."
echo " - Nombre de la red: $network_name"
echo " - Rango de direcciones IP: $start_range - $end_range"
echo " - Dirección IP del servidor DHCP: $server_ip"

