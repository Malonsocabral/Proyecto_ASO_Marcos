#!/bin/bash

# Defino el número máximo de conexiones antes de considerar una IP sospechosa
conexiones=100

# Este es el archivo de logs de Apache donde revisaré las conexiones
logs="/var/log/apache2/access.log"

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
    if [ -z "$ip" ]; then
        echo "Error: IP no válida."
        return
    fi

    echo "Bloqueando IP: $ip"
    sudo iptables -A INPUT -s "$ip" -j DROP
    echo "$ip" >> "$ips_bloqueadas"

    # Bloquear IPs en el mismo rango (primeros 3 octetos)
    rango_ip=$(echo "$ip" | cut -d '.' -f 1-3)
    if [ -z "$rango_ip" ]; then
        echo "Error: No se pudo calcular el rango de IPs."
        return
    fi

    echo "Bloqueando rango de IPs: $rango_ip.0/24"
    sudo iptables -A INPUT -s "$rango_ip.0/24" -j DROP
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
    while read -r ip_por_ip; do
        # Separo el número de conexiones y la IP
        contador_conexiones=$(echo "$ip_por_ip" | awk '{print $1}')
        ip=$(echo "$ip_por_ip" | awk '{print $2}')
        
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
    done <<< "$ips"
}

# Aqui acaban las funciones y empieza el codigo donde ejecuto las funciones de detección y baneo de ips
detectar_patrones_maliciosos
detectar_conexiones_excesivas

echo "Proceso de mitigación completado."
