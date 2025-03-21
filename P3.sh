#!/bin/bash
# Verifico si el script se ejecutó con sudo
if [ "$EUID" -ne 0 ]
then
    echo "Este script no se ejecuto con sudo. Por favor, ejecutalo como superusuario."
    exit 1
else
    echo "Ejecutando como sudo!"
fi

# Defino el número máximo de conexiones antes de considerar una IP sospechosa
conexiones=100

# Este es el archivo de logs de Apache donde revisaré las conexiones
logs="/var/log/apache2/access.log"
# Este es el fichero que cree para las ip tables
f_iptables="/usr/bin/set_iptables.sh"

# Este es el archivo donde guardo las IPs ya bloqueadas para evitar repetir bloqueos
ips_bloqueadas="/var/log/ips_bloqueadas.log"

# Creo el archivo de IPs bloqueadas si no existe
touch "$ips_bloqueadas"

# Este es la función para enviar un correo electrónico a mi correo personal
enviar_correo() {
    correo_destinatario=$(grep "root=" /etc/ssmtp/ssmtp.conf | cut -d'=' -f2) # Aqui entro en el fichero de configuracion del email para sacar el correo
    ip=$1
    rango=$2
    asunto="IP o Rango Bloqueado"
    mensaje="Se ha bloqueado la IP: $ip y el rango: $rango en el servidor."
    #sudo apt install mailutils -y &> /dev/null # Instalo la herramienta para mandar emails sino esta intalada
    echo "$mensaje" | mail -s "$asunto" $correo_destinatario
}

# Este es la función que usare para bloquear una IP y su rango
bloquear_ip() {
    ip=$1
    if [ -z "$ip" ]
    then
        echo "Error: IP no válida."
        return
    fi
    # Bloqueamos la ip añadiendolo al final de nuestro fichero de ip tables y ejecutandolo.
    echo "Bloqueando IP: $ip"
    echo "#Bloqueando la ip: $ip
    iptables -A INPUT -s "$ip" -j DROP" >> $f_iptables
    sudo $f_iptables 
    echo "$ip" >> "$ips_bloqueadas"

    # Bloquear IPs en el mismo rango (primeros 3 octetos)
    rango_ip=$(echo "$ip" | cut -d '.' -f 1-3)
    if [ -z "$rango_ip" ]
    then
        echo "Error: No se pudo calcular el rango de IPs."
        return
    fi
    # Bloqueamos el rango de ips añadiendolo al final de nuestro fichero de ip tables y ejecutandolo.
    echo "Bloqueando rango de IPs: $rango_ip.0/24"
    echo "#Bloqueando el rango de ips: '$rango_ip.0/24'
    iptables -A INPUT -s '$rango_ip.0/24' -j DROP" >> $f_iptables
    sudo $f_iptables 
    # Debido a un error mencionado en el apartado de errores de la memoria implemento el siguiente codigo
    if [ "$rango_ip.0/24" != ".0/24" ]
    then
    echo "$rango_ip.0/24" >> "$ips_bloqueadas"
    fi
    # Llamo a la funcion para enviar correo electrónico
    enviar_correo "$ip" "$rango_ip.0/24"
}

# Este es la función para detectar patrones maliciosos en los logs
detectar_patrones_maliciosos() {
    # Defino los patrones sospechosos que quiero buscar en los logs
    patrones_maliciosos=("sqlmap" "nikto" "nmap" "hydra")

    # Recorro cada patrón en la lista de patrones maliciosos
    for patron in "${patrones_maliciosos[@]}"
    do
        echo "Buscando patrón: $patron"

        # Extraigo las IPs que coinciden con el patrón en los logs
        ips_sospechosas=$(grep -i "$patron" "$logs" | awk '{print $1}' | sort | uniq)

        # Recorro cada IP sospechosa
        for ip in $ips_sospechosas
        do
            # Variable para verificar si la IP ya está bloqueada
            ip_encontrada=0

            # Recorro el archivo de IPs bloqueadas para ver si la IP ya está en la lista
            for ip_bloqueada in $(cat "$ips_bloqueadas")
            do
                if [ "$ip" = "$ip_bloqueada" ]
                then
                    ip_encontrada=1
                    break
                fi
            done

            # Si la IP no está bloqueada, la bloqueo
            if [ "$ip_encontrada" -eq 0 ]
            then
                echo "IP sospechosa detectada: $ip (Patrón: $patron)"
                bloquear_ip "$ip"
            else
                echo "La IP $ip ya está bloqueada."
            fi
        done
    done
}

# Este es la función que uso para detectar IPs con muchas conexiones
detectar_conexiones_excesivas() {
    echo "Analizando conexiones excesivas..."

    # Extraigo las IPs del log de Apache, cuento cuántas veces aparecen y las ordeno de mayor a menor
    ips=$(awk '{print $1}' "$logs" | sort | uniq -c | sort -nr)

    # Recorro cada línea de la lista de IPs y sus conexiones
    for ip_por_ip in ips
    do
        # Separo el número de conexiones y la IP
        contador_conexiones=$(echo "$ip_por_ip" | awk '{print $1}')
        ip=$(echo "$ip_por_ip" | awk '{print $2}')

#Antes de hacer la comparacion de conexiones, reviso si es un valor nulo, (si no hay logs de apache), si es nulo, paro el script ya que no hay logs.
#if [ "$contador_conexiones" == "" ]
#then
#    echo "Error: No hay logs de apache, terminando el proceso de mitigacion ... "
#    exit 2
#fi
        # Si la IP supera el umbral de conexiones, la bloqueo
        if [ "$contador_conexiones" -gt "$conexiones" ]
        then
         
            # Variable para verificar si la IP ya está bloqueada
            ip_encontrada=0

            # Recorro el archivo de IPs bloqueadas para ver si la IP ya está en la lista
            for ip_bloqueada in $(cat "$ips_bloqueadas")
            do
                if [ "$ip" = "$ip_bloqueada" ]
                then
                    ip_encontrada=1
                    break
                fi
            done

            # Si la IP no está bloqueada, la bloqueo
            if [ "$ip_encontrada" -eq 0 ]
            then
                echo "IP con conexiones excesivas detectada: $ip - Conexiones: $contador_conexiones"
                bloquear_ip "$ip"
            else
                echo "La IP $ip ya está bloqueada."
            fi
        fi
    done
}

# Aqui acaban las funciones y empieza el codigo donde ejecuto las funciones de detección y baneo de ips
detectar_patrones_maliciosos
detectar_conexiones_excesivas

# Obtengo la hora actual (solo los minutos) para asi cuando sea en punto, vaciar el fichero iptables y poner el que tiene mi script de Montage de Ubuntu, y tambien borrar las ip bloqueadas y rangos.
minutos=$(date +%M)
hora=$(date +%H)
logs_antiguos_apache2=/var/log/apache2/logs-eliminados-access.log

# Verificar si es la hora en punto (minutos == 00)
if [ "$minutos" -eq "00" ]
then
    echo "Son las $hora en PUNTO (.$minutos)"
    echo "Por lo tanto, procedemos a borrar las iptables de las ips y rangos añadidos"
    echo "Ademas borramos los logs de apache, cambiandolos a un fichero nuevo llamado '$logs_antiguos_apache2' "
    echo "" > "$f_iptables"  # Esto vacía el fichero de ip tables

    # Y a continuacion volvemos a poner el fichero inicial de ip tables 

    sudo echo "#!/bin/bash

# Limpio todas las reglas de iptables y las de la tabla NAT
iptables -F
iptables -t nat -F

# Enmascaro las IPs de la red 192.168.0.0/24 cuando salen por enp0s3 (como un router)
iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.0.0/24 -j MASQUERADE

# Permito que el tráfico de la red 192.168.0.0/24 pase de enp0s8 a enp0s3
iptables -A FORWARD -i enp0s8 -o enp0s3 -s 192.168.0.0/24 -j ACCEPT

# Permito que el tráfico ya establecido o relacionado vuelva de enp0s3 a enp0s8
iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT" > /usr/bin/set_iptables.sh

    sudo /usr/bin/set_iptables.sh #Ejecuto estas reglas que acabo de crear

# A continuacion vacio tambien los logs de apache cambiandolos 
    sudo cat "$logs" >> $logs_antiguos_apache2
    sudo echo "" > $logs
    echo "Ficheros Cambiados y eliminados correctamente."
    echo
else
    echo
    echo "Aun no es la hora en punto, por lo que no se vaciaran ni los logs de apache ni las iptables."
fi
echo
echo "Proceso de mitigación completado."
