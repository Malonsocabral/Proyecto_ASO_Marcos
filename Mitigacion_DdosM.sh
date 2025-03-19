#!/bin/bash

# Defino el número máximo de conexiones antes de considerar una IP sospechosa
conexiones=100

# Archivo de logs de Apache donde revisaré las conexiones
logs="/var/log/apache2/access.log"

# Archivo donde guardo las IPs ya bloqueadas para evitar repetir bloqueos
ips_bloqueadas="/var/log/ips_bloqueadas.log"

# Creo el archivo de IPs bloqueadas si no existe
touch $ips_bloqueadas

# Extraigo las IPs del log de Apache, cuento cuántas veces aparecen y las ordeno de mayor a menor
ips=$(awk '{print $1}' $logs | sort | uniq -c | sort -nr)

# Recorro cada línea de la lista de IPs y sus conexiones
for ip_por_ip in $ips
do
    # Separo el número de conexiones y la IP
    contador_conexiones=$(echo $ip_por_ip | awk '{print $1}')
    ip=$(echo $ip_por_ip | awk '{print $2}')
    
    if [ $contador_conexiones -gt $conexiones ]
    then
    # Recorro el archivo de IPs bloqueadas con un bucle for
        for ip_bloqueada in $(cat $ips_bloqueadas)
        do
            if [ "$ip" = "$ip_bloqueada" ]
            then
                echo "La IP $ip ya está bloqueada, no hago nada."
            else
               # Si la IP supera el umbral, la bloqueo
                echo "Bloqueando IP: $ip - Conexiones: $contador_conexiones"
            
                # Agrego la IP a iptables para bloquear su tráfico
                sudo iptables -A INPUT -s $ip -j DROP

                # Guardo la IP en el archivo para recordar que ya fue bloqueada
                echo "$ip" >> $ips_bloqueadas
            fi
        done
    else 
         echo "La ip $ip no supera las $conexiones conexiones en este servidor"
         echo ""
    fi
done

echo "Proceso de mitigación completado."

crontab -e
*/5 * * * * /ruta/a/tu/script.sh
