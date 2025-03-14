function help1 {
echo
echo "Bienvenido a las configuracion de ubuntuserver de Marcos"
echo "A continuacion voy a ir preguntando si quieres ir instalando cada configuracion"
echo "Si no quieres instalar alguna configuracion simplemente pon la letra 'n' y si deseas aplicar la configuracion de este script, simplemente dale a 'Enter' o con la letra 's'"
echo
echo "Ire guiandote en cada paso avisandote antes de hacer cada instruccion importante si quieres realizarla o no"
echo
echo "Una vez dicho esto..."
}
#le doy permisos a todos los ficheros que modificaremos
sudo chmod 777 /etc/netplan/50-cloud-init.yaml



if [ "$1" == "--help" -o "$1" == "-h" ] # Explicacion del comando con --help
then
    help1
fi
echo -e "\e[34m\e[47mPara obtener mas informacion pon '-- help' o '-h' en el primer parametro \033[0 \e[39m \e[49m"
#hacemos un bucle por si respondes mal la primera pregunta.
while true ;
do
	read -rep "Sabes como va a funcionar este script? (s/n)" tutorial
	#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $tutorial ]
    then
        break
    elif [ $tutorial == "s" ]
    then
		echo "Perfecto, comenzamos..."
        break
    elif [ $tutorial == "n" ]
    then
        help1
        break
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done
echo
echo "1. Comenzamos con las actualizaciones generales con un sudo apt update"
sudo apt update
confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "2. Procedemos a instalar el servicio dhcp 'sudo apt install isc-dhcp-server' (s/n)" dhcp
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $dhcp ]
    then
    sudo apt install isc-dhcp-server

        confirmacion="s"
    elif [ $dhcp == "s" ]
    then
    sudo apt install isc-dhcp-server

        confirmacion="s"
    elif [ $dhcp == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done

#sudo nano /etc/netplan/50-cloud-init.yaml
confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "3. Procedemos a configurar el fichero '/etc/netplan/50-cloud-init.yaml' para crear dos interfaces de red (s/n)" netplan
    sudo chmod 777 /etc/netplan/50-cloud-init.yaml #le doy permisos (ire haciendo esto a lo largo del script)
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $netplan ]
    then
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
	confirmacion="s"

    elif [ $netplan == "s" ]
    then
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

        confirmacion="s"
    elif [ $netplan == "n" ]
    then
     echo   "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done
sudo netplan apply
confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "4. Procedemos copiar este fichero '/etc/netplan/50-cloud-init.yaml'  en otro nuevo '/etc/netplan/50-cloud-init.yaml.bckp' para hacer una copia de segurida y podamos restaurarlo cuando reiniciamos el servidor (s/n)" netplanbp
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $netplanbp ]
    then
    sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bckp #Copiamos el .yaml
	confirmacion="s"

    elif [ $netplanbp == "s" ]
    then
    sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bckp #Copiamos el .yaml

        confirmacion="s"
    elif [ $netplanbp == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done

confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "5. Procedemos a configurar el fichero '/etc/default/isc-dhcp-server' para cambiar las configuraciones del servidor dhcp (s/n)" dhcpconf
    sudo chmod 777 /etc/default/isc-dhcp-server
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $dhcpconf ]
    then
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

	confirmacion="s"

    elif [ $dhcpconf == "s" ]
    then
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

        confirmacion="s"
    elif [ $dhcpconf == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done

confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "6. Procedemos a activar la interfaz enp0s8 y luego enp0s3 (para tener conexion ya que el enpos3 es el adaptador NAT) y luego hacer restart en el servidor dchp junto con su status (s/n)" activaryrestart
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $activaryrestart ]
    then
sudo ip link set enp0s8 up
sudo ip link set enp0s3 up
sudo service isc-dhcp-server restart
sudo service isc-dhcp-server status

	confirmacion="s"

    elif [ $activaryrestart == "s" ]
    then
    sudo ip link set enp0s8 up
sudo ip link set enp0s3 up
sudo service isc-dhcp-server restart
sudo service isc-dhcp-server status

        confirmacion="s"
    elif [ $activaryrestart == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done

confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "7. Procedemos a instalarel servicio de DNS (bind9) (s/n)" bind9
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $bind9 ]
    then
sudo apt install bind9 bind9utils bind9-doc
	confirmacion="s"

    elif [ $bind9 == "s" ]
    then
sudo apt install bind9 bind9utils bind9-doc
        confirmacion="s"
    elif [ $bind9 == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done


#sudo nano /etc/hosts
confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "8. Procedemos a comfigurar el fichero '/etc/hosts' para configurar las ip de nuestro servidor y todo lo demas (s/n)" host
    sudo chmod 777 /etc/hosts
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $host ]
    then
sudo echo "127.0.0.1 marcos.dc.org
127.0.1.1 marcos

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters" > /etc/hosts
	confirmacion="s"

    elif [ $host == "s" ]
    then
sudo echo "127.0.0.1 marcos.dc.org
127.0.1.1 marcos

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters" > /etc/hosts

        confirmacion="s"
    elif [ $host == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done

#sudo nano /etc/bind/named.conf.local
confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "9. Procedemos a comfigurar el fichero '/etc/bind/named.conf.local' para configurar las el servidor DNS escribiendo las zonas (s/n)" zonas
    sudo chmod 777 /etc/bind/named.conf.local
   
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $zonas ]
    then

sudo echo "//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "marcos.dc.org" {
	type master;
	file "/etc/bind/db.marcos.dc.org";
};

zone "0.168.192.in-addr.arpa" {
	type master;
	file "/etc/bind/db.192.168.0";

};" > /etc/bind/named.conf.local
	confirmacion="s"

    elif [ $zonas == "s" ]
    then

sudo echo "//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "marcos.dc.org" {
	type master;
	file "/etc/bind/db.marcos.dc.org";
};

zone "0.168.192.in-addr.arpa" {
	type master;
	file "/etc/bind/db.192.168.0";

};" > /etc/bind/named.conf.local

        confirmacion="s"
    elif [ $zonas == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done



confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "10. Procedemos a copiar el archivo '/etc/bind/db.local' en '/etc/bind/db.marcos.dc.org' ( que es el nombre del dominio de este script) y lo configuramos con todas las configuraciones de mi dominio (s/n)" dbmarcosdcorg
    
    
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $dbmarcosdcorg ]
    then
sudo cp /etc/bind/db.local /etc/bind/db.marcos.dc.org
sudo chmod 777 /etc/bind/db.marcos.dc.org
#sudo nano etc/bind/db.marcos.dc.org
sudo echo ";
; BIND data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.marcos.dc.org. root.marcos.dc.org. (
			      2		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	ns1.marcos.dc.org.
ns1	IN	A	192.168.0.1" > /etc/bind/db.marcos.dc.org
	confirmacion="s"

    elif [ $dbmarcosdcorg == "s" ]
    then
sudo cp /etc/bind/db.local /etc/bind/db.marcos.dc.org
sudo chmod 777 /etc/bind/db.marcos.dc.org
#sudo nano etc/bind/db.marcos.dc.org
sudo echo ";
; BIND data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.marcos.dc.org. root.marcos.dc.org. (
			      2		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	ns1.marcos.dc.org.
ns1	IN	A	192.168.0.1" > /etc/bind/db.marcos.dc.org
        confirmacion="s"
    elif [ $dbmarcosdcorg == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done

confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "11. Procedemos a copiar el archivo '/etc/bind/db.127' en '/etc/bind/db.192.168' ( que es el nombre de la zona negativa del dominio de este script) y lo configuramos con todas las configuraciones de mi zona negativa de mi dominio (s/n)" db192168
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $db192168 ]
    then
sudo cp /etc/bind/db.127 /etc/bind/db.192.168.0
sudo chmod 777 /etc/bind/db.192.168.0
#sudo nano /etc/bind/db.192.168.0
sudo echo ";
; BIND reverse data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.marcos.castelao.org. root.marcos.dc.org. (
			      1		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	ns1.marcos.dc.org.
1	IN	PTR	ns1.marcos.dc.org." > /etc/bind/db.192.168.0
	confirmacion="s"

    elif [ $db192168 == "s" ]
    then
sudo cp /etc/bind/db.127 /etc/bind/db.192.168.0
sudo chmod 777 /etc/bind/db.192.168.0
#sudo nano /etc/bind/db.192.168.0
sudo echo ";
; BIND reverse data file for local loopback interface
;
$TTL	604800
@	IN	SOA	ns1.marcos.castelao.org. root.marcos.dc.org. (
			      1		; Serial
			 604800		; Refresh
			  86400		; Retry
			2419200		; Expire
			 604800 )	; Negative Cache TTL
;
@	IN	NS	ns1.marcos.dc.org.
1	IN	PTR	ns1.marcos.dc.org." > /etc/bind/db.192.168.0
        confirmacion="s"
    elif [ $db192168 == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done
#siguientes pasos serian---
#sudo named-checkconf
#sudo named-checkconf /etc/bind/named.conf
#sudo named-chechzone marcos.dc.org /etc/bind/db.marcos.dc.org
#sudo named-checkzone 0.168.192.in-addr.arpa /etc/bin/db.192.168.0
#sudo service named restart

confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "12. Procedemos configurarlos servidores forwarders y desactivar la dnssec-validation en el fichero '/etc/bind/named.conf.options' (s/n)" namedconfoptions
    sudo chmod 777 /etc/bind/named.conf.options
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $namedconfoptions ]
    then
#sudo nano /etc/bind/named.conf.options
sudo echo "options {
	directory "/var/cache/bind";

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
	confirmacion="s"

    elif [ $namedconfoptions == "s" ]
    then
#sudo nano /etc/bind/named.conf.options
sudo echo "options {
	directory "/var/cache/bind";

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
        confirmacion="s"
    elif [ $namedconfoptions == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done







#/etc/dhcp/dhcpd.conf -----------------se modifica antes pero ahora se deja el definitivo
#sudo service restart

confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "13. Procedemos a configurar el fichero '/etc/sysctl.conf' para que acepte redireciones de ipv4 y funcione correctamente (cabe destacar que luego ya aplicamos los cambios) (s/n)" sysctlconf
    sudo chmod 777 /etc/sysctl.conf
   
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $sysctlconf ]
    then

#sudo nano /etc/sysctl.conf

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
	confirmacion="s"

    elif [ $sysctlconf == "s" ]
    then

#sudo nano /etc/sysctl.conf

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
        confirmacion="s"
    elif [ $sysctlconf == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done


confirmacion="n"
while [ "$confirmacion" != "s" ]
do
echo
    read -rep "14. Procedemos a crear y configurar las iptables del servidor en el directorio '/usr/bin/set_iptables.sh' (s/n)" iptablessh
#El -z hace que si le das a 'Enter' salte directamente y fuese como si pusieses una 's'
    if [ -z $iptablessh ]
    then
sudo touch /usr/bin/set_iptables.sh
sudo chmod 777 /usr/bin/set_iptables.sh
#sudo nano /usr/bin/set_iptables.sh
echo "iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.0.0/24 -j MASQUERADE
iptables -A FORWARD -i enp0s8 -o enp0s3 -s 192.168.0.0/24 -j ACCEPT
iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
" > /usr/bin/set_iptables.sh

sudo /usr/bin/set_iptables.sh
#sudo iptables -L
	confirmacion="s"

    elif [ $iptablessh == "s" ]
    then
sudo touch /usr/bin/set_iptables.sh
sudo chmod 777 /usr/bin/set_iptables.sh
#sudo nano /usr/bin/set_iptables.sh
echo "iptables -F
iptables -t nat -F
iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.0.0/24 -j MASQUERADE
iptables -A FORWARD -i enp0s8 -o enp0s3 -s 192.168.0.0/24 -j ACCEPT
iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
" > /usr/bin/set_iptables.sh

sudo /usr/bin/set_iptables.sh
#sudo iptables -L
        confirmacion="s"
    elif [ $iptablessh == "n" ]
    then
       echo "Saltando el paso ..."
        confirmacion="s"
    else
        echo -e "\e[47m--Error, el valor introducido no es ni 's' ni 'n'\e[49m"
        echo
    fi
done


echo " Y por ultimo hacermos restart del servidor DNS y DHCP para que funcionen correctamente."
sudo service named restart
sudo service isc-dhcp-server restart
echo
echo "Todo correcto"
echo
echo "Finalizando script..."
















