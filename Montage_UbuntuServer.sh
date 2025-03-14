#!/bin/bash
# Colores para los mensajes
rojo='\033[0;31m'
verde='\033[0;32m'
amarillo='\033[1;33m'
azul='\033[0;34m'
magenta='\033[0;35m'
cyan='\033[0;36m'
nc='\033[0m' # No Color
TTL='$TTL'
# Función de ayuda
function help1 {
    echo
    echo -e "$verde Bienvenido a las configuracion de ubuntuserver de Marcos $nc"
    echo -e "$verde A continuacion voy a ir preguntando si quieres ir instalando cada configuracion $nc"
    echo -e "$verde Si no quieres instalar alguna configuracion simplemente pon la letra 'n' y si deseas aplicar la configuracion de este script, simplemente dale a 'Enter' o con la letra 's' $nc"
    echo
    echo -e "$verde Ire guiandote en cada paso avisandote antes de hacer cada instruccion importante si quieres realizarla o no $nc"
    echo
    echo -e "$verde Una vez dicho esto... $nc"
}

# Pedir al usuario el nombre del dominio
echo -e "$cyan Por favor, introduce el nombre del dominio (por ejemplo, ola.host): $nc"
read Nombre_dominio

# Le doy permisos a todos los ficheros que modificaremos
sudo chmod 777 /etc/netplan/50-cloud-init.yaml

if [ "$1" == "--help" -o "$1" == "-h" ] # Explicacion del comando con --help
then
    help1
fi
echo -e "$azul Para obtener mas informacion pon '--help' o '-h' en el primer parametro $nc"

echo -e "$amarillo 1. Comenzamos con las actualizaciones generales con un sudo apt update $nc"
sleep 2
sudo apt update

echo -e "$amarillo 2. Procedemos a instalar el servicio dhcp 'sudo apt install isc-dhcp-server' $nc"
sleep 2
sudo apt install isc-dhcp-server

# Añadir el contenido en /etc/dhcp/dhcpd.conf
echo -e "$amarillo Añadiendo configuración en /etc/dhcp/dhcpd.conf... $nc"
sleep 2
sudo echo "# dhcpd.conf
#
# Sample configuration file for ISC dhcpd
#
# Attention: If /etc/ltsp/dhcpd.conf exists, that will be used as
# configuration file instead of this file.
#

# option definitions common to all supported networks...
# option domain-name \"example.org\";
# option domain-name-servers ns1.example.org, ns2.example.org;

default-lease-time 600;
max-lease-time 7200;

# The ddns-updates-style parameter controls whether or not the server will
# attempt to do a DNS update when a lease is confirmed. We default to the
# behavior of the version 2 packages ('none', since DHCP v2 didn't
# have support for DDNS.)
ddns-update-style none;

# If this DHCP server is the official DHCP server for the local
# network, the authoritative directive should be uncommented.
authoritative;

# Use this to send dhcp log messages to a different log file (you also
# have to hack syslog.conf to complete the redirection).
#log-facility local7;

# No service will be given on this subnet, but declaring it helps the
# DHCP server to understand the network topology.

#subnet 10.152.187.0 netmask 255.255.255.0 {
#}

# This is a very basic subnet declaration.

#subnet 10.254.239.0 netmask 255.255.255.224 {
#  range 10.254.239.10 10.254.239.20;
#  option routers rtr-239-0-1.example.org, rtr-239-0-2.example.org;
#}

# This declaration allows BOOTP clients to get dynamic addresses,
# which we don't really recommend.

#subnet 10.254.239.32 netmask 255.255.255.224 {
#  range dynamic-bootp 10.254.239.40 10.254.239.60;
#  option broadcast-address 10.254.239.31;
#  option routers rtr-239-32-1.example.org;
#}

# A slightly different configuration for an internal subnet.
subnet 192.168.0.0 netmask 255.255.255.000 {
  range 192.168.0.2 192.168.0.254;
  option domain-name-servers 192.168.0.1,8.8.8.8 ;
  option domain-name \"$Nombre_dominio\";
  option subnet-mask 255.255.255.0;
  option routers 192.168.0.1;
  option broadcast-address 192.168.0.255;
  default-lease-time 600;
  max-lease-time 7200;
}

zone $Nombre_dominio. {
	primary 127.0.0.1;

}

zone 0.168.192.in-addr.arpa. {
	primary 127.0.0.1;

}

# Hosts which require special configuration options can be listed in
# host statements.   If no address is specified, the address will be
# allocated dynamically (if possible), but the host-specific information
# will still come from the host declaration.

#host passacaglia {
#  hardware ethernet 0:0:c0:5d:bd:95;
#  filename \"vmunix.passacaglia\";
#  server-name \"toccata.example.com\";
#}

# Fixed IP addresses can also be specified for hosts.   These addresses
# should not also be listed as being available for dynamic assignment.
# Hosts for which fixed IP addresses have been specified can boot using
# BOOTP or DHCP.   Hosts for which no fixed address is specified can only
# be booted with DHCP, unless there is an address range on the subnet
# to which a BOOTP client is connected which has the dynamic-bootp flag
# set.
#host fantasia {
#  hardware ethernet 08:00:07:26:c0:a5;
#  fixed-address fantasia.example.com;
#}

# You can declare a class of clients and then do address allocation
# based on that.   The example below shows a case where all clients
# in a certain class get addresses on the 10.17.224/24 subnet, and all
# other clients get addresses on the 10.0.29/24 subnet.

#class \"foo\" {
#  match if substring (option vendor-class-identifier, 0, 4) = \"SUNW\";
#}

#shared-network 224-29 {
#  subnet 10.17.224.0 netmask 255.255.255.0 {
#    option routers rtr-224.example.org;
#  }
#  subnet 10.0.29.0 netmask 255.255.255.0 {
#    option routers rtr-29.example.org;
#  }
#  pool {
#    allow members of \"foo\";
#    range 10.17.224.10 10.17.224.250;
#  }
#  pool {
#    deny members of \"foo\";
#    range 10.0.29.10 10.0.29.230;
#  }
#}" > /etc/dhcp/dhcpd.conf

echo -e "$amarillo 3. Procedemos a configurar el fichero '/etc/netplan/50-cloud-init.yaml' para crear dos interfaces de red $nc"
sleep 2
sudo chmod 777 /etc/netplan/50-cloud-init.yaml
sudo echo -e "# This file is generated from information provided by the datasource.  Changes
# to it will not persist across an instance reboot.  To disable cloud-init's
# network configuration capabilities, write a file
# /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg with the following:
# network: {config: disabled}
network:
    ethernets:
        enp0s3:
            dhcp4: true
        enp0s8:
            dhcp4: false
            addresses:
            - 192.168.0.1/24
            nameservers:
             addresses: [192.168.0.1,8.8.8.8]
    version: 2" > /etc/netplan/50-cloud-init.yaml
sudo netplan apply

echo -e "$amarillo 4. Procedemos copiar este fichero '/etc/netplan/50-cloud-init.yaml' en otro nuevo '/etc/netplan/50-cloud-init.yaml.bckp' para hacer una copia de seguridad $nc"
sleep 2
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bckp

echo -e "$amarillo 5. Procedemos a configurar el fichero '/etc/default/isc-dhcp-server' para cambiar las configuraciones del servidor dhcp $nc"
sleep 2
sudo chmod 777 /etc/default/isc-dhcp-server
sudo echo '# Defaults for isc-dhcp-server (sourced by /etc/init.d/isc-dhcp-server)

# Path to dhcpds config file (default: /etc/dhcp/dhcpd.conf).
#DHCPDv4_CONF=/etc/dhcp/dhcpd.conf
#DHCPDv6_CONF=/etc/dhcp/dhcpd6.conf

# Path to dhcpds PID file (default: /var/run/dhcpd.pid).
#DHCPDv4_PID=/var/run/dhcpd.pid
#DHCPDv6_PID=/var/run/dhcpd6.pid

# Additional options to start dhcpd with.
#	Dont use options -cf or -pf here; use DHCPD_CONF/ DHCPD_PID instead
#OPTIONS=""

# On what interfaces should the DHCP server (dhcpd) serve DHCP requests?
#	Separate multiple interfaces with spaces, e.g. "eth0 eth1".
INTERFACESv4="enp0s8"
INTERFACESv6=""' > /etc/default/isc-dhcp-server

echo -e "$amarillo 6. Procedemos a activar la interfaz enp0s8 y luego enp0s3 y luego hacer restart en el servidor dhcp junto con su status $nc"
sleep 2
sudo ip link set enp0s8 up
sudo ip link set enp0s3 up
sudo service isc-dhcp-server restart
sudo service isc-dhcp-server status

echo -e "$amarillo 7. Procedemos a instalar el servicio de DNS (bind9) $nc"
sleep 2
sudo apt install bind9 bind9utils bind9-doc

echo -e "$amarillo 8. Procedemos a configurar el fichero '/etc/hosts' para configurar las ip de nuestro servidor $nc"
sleep 2
sudo chmod 777 /etc/hosts
sudo echo "127.0.0.1 $Nombre_dominio
127.0.1.1 $Nombre_dominio

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters" > /etc/hosts

echo -e "$amarillo 9. Procedemos a configurar el fichero '/etc/bind/named.conf.local' para configurar las zonas $nc"
sleep 2
sudo chmod 777 /etc/bind/named.conf.local
sudo echo "//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include \"/etc/bind/zones.rfc1918\";

zone \"$Nombre_dominio\" {
	type master;
	file \"/etc/bind/db.$Nombre_dominio\";
};

zone \"0.168.192.in-addr.arpa\" {
	type master;
	file \"/etc/bind/db.192.168.0\";

};" > /etc/bind/named.conf.local

echo -e "$amarillo 10. Procedemos a copiar el archivo '/etc/bind/db.local' en '/etc/bind/db.$Nombre_dominio' y lo configuramos $nc"
sleep 2
sudo cp /etc/bind/db.local /etc/bind/db.$Nombre_dominio
sudo chmod 777 /etc/bind/db.$Nombre_dominio
sudo echo ";
; BIND data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.$Nombre_dominio. root.$Nombre_dominio. (
			      2		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	ns1.$Nombre_dominio.
ns1	IN	A	192.168.0.1" > /etc/bind/db.$Nombre_dominio

echo -e "$amarillo 11. Procedemos a copiar el archivo '/etc/bind/db.127' en '/etc/bind/db.192.168' y lo configuramos $nc"
sleep 2
sudo cp /etc/bind/db.127 /etc/bind/db.192.168.0
sudo chmod 777 /etc/bind/db.192.168.0
sudo echo ";
; BIND reverse data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.$Nombre_dominio. root.$Nombre_dominio. (
			      1		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	ns1.$Nombre_dominio.
1	IN	PTR	ns1.$Nombre_dominio." > /etc/bind/db.192.168.0

echo -e "$amarillo 12. Procedemos configurar los servidores forwarders y desactivar la dnssec-validation en el fichero '/etc/bind/named.conf.options' $nc"
sleep 2
sudo chmod 777 /etc/bind/named.conf.options
sudo echo "options {
	directory \"/var/cache/bind\";

	// If there is a firewall between you and nameservers you want
	// to talk to, you may need to fix the firewall to allow multiple
	// ports to talk.  See http://www.kb.cert.org/vuls/id/800113

	// If your ISP provided one or more IP addresses for stable
	// nameservers, you probably want to use them as forwarders.
	// Uncomment the following block, and insert the addresses replacing
	// the all-0's placeholder.

	 forwarders {
		8.8.8.8;
		8.8.4.4;
	 };

	//========================================================================
	// If BIND logs error messages about the root key being expired,
	// you will need to update your keys.  See https://www.isc.org/bind-keys
	//========================================================================
	dnssec-validation no;

	listen-on-v6 { any; };
};" > /etc/bind/named.conf.options

echo -e "$amarillo 13. Procedemos a configurar el fichero '/etc/sysctl.conf' para que acepte redirecciones de ipv4 y funcione correctamente $nc"
sleep 2
sudo chmod 777 /etc/sysctl.conf
sudo echo "#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#

#kernel.domainname = example.com

# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3

###################################################################
# Functions previously found in netbase
#

# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
#net.ipv4.conf.all.rp_filter=1

# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1

# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1

# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1


###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
# Accept ICMP redirects only for gateways listed in our default
# gateway list (enabled by default)
# net.ipv4.conf.all.secure_redirects = 1
#
# Do not send ICMP redirects (we are not a router)
#net.ipv4.conf.all.send_redirects = 0
#
# Do not accept IP source route packets (we are not a router)
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv6.conf.all.accept_source_route = 0
#
# Log Martian Packets
#net.ipv4.conf.all.log_martians = 1
#

###################################################################
# Magic system request Key
# 0=disable, 1=enable all, >1 bitmask of sysrq functions
# See https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html
# for what other values do
#kernel.sysrq=438
" > /etc/sysctl.conf
sudo sysctl -p

echo -e "$amarillo 14. Procedemos a crear y configurar las iptables del servidor en el directorio '/usr/bin/set_iptables.sh' $nc"
sleep 2
sudo touch /usr/bin/set_iptables.sh
sudo chmod 777 /usr/bin/set_iptables.sh
sudo echo "iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.0.0/24 -j MASQUERADE
iptables -A FORWARD -i enp0s8 -o enp0s3 -s 192.168.0.0/24 -j ACCEPT
iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
" > /usr/bin/set_iptables.sh

sudo /usr/bin/set_iptables.sh

echo -e "$verde Y por ultimo hacemos restart del servidor DNS y DHCP para que funcionen correctamente. $nc"
sudo service named restart
sudo service isc-dhcp-server restart

echo
echo -e "$verde Todo correcto $nc"
echo
echo -e "$verde Finalizando script... $nc"
