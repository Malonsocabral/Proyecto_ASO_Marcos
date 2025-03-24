#!/bin/bash
# Verifico si el script se ejecutó con sudo
if [ "$EUID" -ne 0 ]
then
    echo "Este script no se ejecuto con sudo. Por favor, ejecutalo como superusuario."
    exit 1
else
    echo "Ejecutando como sudo!"
fi
# Pongo la siguiente regla de ip tables para permitir la ip 192.168.0.1 (que es el server) para poder hacer comprobaciones con TIME, ya que al bloquear un rango se me bloquea la ip del server. ( este error ya esta explicado en la memoria )
sudo iptables -I INPUT -s "192.168.0.1" -j ACCEPT

# Comienzo definiendo el número máximo de conexiones antes de considerar una IP sospechosa ( esto se puede cambiar a gusto de como se quiera )
conexiones=100

# Este es el archivo de logs de Apache donde revisaré las conexiones
logs="/var/log/apache2/access.log"
# Este es el fichero que cree para las ip tables (ya en el script de Ubuntu)
f_iptables="/usr/bin/set_iptables.sh"

# Este es el archivo donde guardo las IPs ya bloqueadas para evitar repetir bloqueos innecesarios
ips_bloqueadas="/var/log/ips_bloqueadas.log"

# Creo el archivo de IPs bloqueadas si no existe
touch "$ips_bloqueadas"

# Esta es la función para enviar un correo electrónico a mi correo personal ( que se puede configurar en el fichero .sh de 020-correo )
enviar_correo() {
    correo_destinatario=$(grep "root=" /etc/ssmtp/ssmtp.conf | cut -d'=' -f2) # Aqui entro en el fichero de configuracion del email para sacar el correo
    ip=$1
    rango=$2
    asunto="IP o Rango Bloqueado"
    mensaje="Se ha bloqueado la IP: $ip y el rango: $rango en el servidor."
    #sudo apt install mailutils -y &> /dev/null # Instalo la herramienta para mandar emails sino esta intalada
    echo "$mensaje" | mail -s "$asunto" $correo_destinatario
}

# Esta es la función que usare para bloquear una IP y su rango 
bloquear_ip() {
    ip=$1
    if [ -z "$ip" ]
    then
        echo "Error: IP no válida."
        return
    fi
    # Aqui bloqueo la ip añadiendolo al final de nuestro fichero de ip tables y ejecutandolo.
    echo "Bloqueando IP: $ip"
    echo "#Bloqueando la ip: $ip
    iptables -A INPUT -s "$ip" -j DROP" >> $f_iptables
    sudo $f_iptables 
    echo "$ip" >> "$ips_bloqueadas"

    # Bloqueo IPs en el mismo rango (comparando lo primeros 3 octetos) 
    rango_ip=$(echo "$ip" | cut -d '.' -f 1-3)
    if [ -z "$rango_ip" ]
    then
        echo "Error: No se pudo calcular el rango de IPs."
        return
    fi
    # Hago el siguiente if para que no se bloquee el propio servidor al probar a hacer el ataque desde kali
    if [ "$rango_ip.0/24" != "192.168.0.0/24" ] 
    then
        # Bloqueo el rango de ips añadiendolo al final de nuestro fichero de ip tables y ejecutandolo.
        echo "Bloqueando rango de IPs: $rango_ip.0/24"
        echo "#Bloqueando el rango de ips: '$rango_ip.0/24'
        iptables -A INPUT -s '$rango_ip.0/24' -j DROP" >> $f_iptables
        sudo $f_iptables 
        # Debido a un error mencionado en el apartado de errores de la memoria implemento el siguiente codigo para que si apache no tiene logs no de error
        if [ "$rango_ip.0/24" != ".0/24" ]
        then
        echo "$rango_ip.0/24" >> "$ips_bloqueadas"
        fi
    else
    echo "Como el rango de ips, es el $rango_ip.0/24 y engloba a este propio servidor, no sera bloqueado"
    fi
    # Llamo a la funcion para enviar correo electrónico para que me mande que bloqueo (si bloqueo algo)
    enviar_correo "$ip" "$rango_ip.0/24"
}

# Esta es la función para detectar patrones maliciosos en los logs
detectar_patrones_maliciosos() {
    # Defino los patrones sospechosos que quiero buscar en los logs
    patrones_maliciosos=("sqlmap" "nikto" "nmap" "hydra")

    # Recorro cada patrón en la lista de patrones maliciosos
    for patron in "${patrones_maliciosos[@]}"
    do
        echo "Buscando patrón: $patron"

        # Extraigo las IPs que coinciden con el patrón en los logs con grep y awk ya que me informe y es la mejor manera (mas sencilla)
        ips_sospechosas=$(grep -i "$patron" "$logs" | awk '{print $1}' | sort | uniq)

        # Recorro cada IP sospechosa
        for ip in $ips_sospechosas
        do
            # Esta variable es para verificar si la IP sospechosa ya está bloqueada
            ip_encontrada=0

            # Luego recorro el archivo de IPs bloqueadas para ver si la IP ya está en la lista
            for ip_bloqueada in $(cat "$ips_bloqueadas")
            do
                # Si se encuentra la ip en la lista, se para el bucle y pasa a la siguiente ip ( y no bloquea esta )
                if [ "$ip" = "$ip_bloqueada" ]
                then
                    ip_encontrada=1
                    break
                fi
            done

            # Si la IP no está bloqueada, la bloqueo y la añado al fichero de ips bloqueadas para que no sea bloqueada mas veces
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

# Esta es la función que uso para detectar IPs con muchas conexiones
detectar_conexiones_excesivas() {
    echo "Analizando conexiones excesivas..."

    # Primero extraigo las IPs del log de Apache, cuento cuántas veces aparecen y las ordeno de mayor a menor ( es una manera rebuscada, pero una vez entendida, hace mas facil el proceso de extraer ips )
    ips=$(tr -d '\0' < "$logs" | awk '{print $1}' "$logs" | sort | uniq -c | sort -nr)

    # Recorro cada línea de la lista de IPs y sus conexiones
    while read -r ip_por_ip;
    do
        # Separo el número de conexiones y la IP
        contador_conexiones=$(echo "$ip_por_ip" | awk '{print $1}')
        ip=$(echo "$ip_por_ip" | awk '{print $2}')

# Antes de hacer la comparacion de conexiones, reviso si es un valor nulo, (si no hay logs de apache), si es nulo, paro el script ya que no hay logs.
if [ "$contador_conexiones" == "" ]
then
    echo "Error: No hay logs de apache, terminando el proceso de mitigacion ... "
    exit 2
fi
        # Si la IP supera el umbral de conexiones, la bloqueo
        if [ "$contador_conexiones" -gt "$conexiones" ]
        then
         
            # Esta es una variable para verificar si la IP ya está bloqueada ( es basicamente lo mismo que en la funcion anterior de deteccion de patrones )
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

            # Si la IP no está bloqueada de anteriores veces, la bloqueo
            if [ "$ip_encontrada" -eq 0 ]
            then
                echo "IP con conexiones excesivas detectada: $ip - Conexiones: $contador_conexiones"
                bloquear_ip "$ip"
            else
                echo "La IP $ip ya está bloqueada."
            fi
        fi
    done <<< $ips
}

# Aqui acaban las funciones y empieza el codigo donde ejecuto las funciones de detección y baneo de ips
detectar_patrones_maliciosos
detectar_conexiones_excesivas

# A continuacion paso a la segunda parte del script
# Ya que btengo la hora actual (solo los minutos) para asi cuando sea en punto, vaciar el fichero iptables ( asi poner el que tiene mi script de Montage de Ubuntu ), tambien borrar las ip bloqueadas y rangos, y cambia los logs de apache haciendo una copia.
minutos=$(date +%M)
hora=$(date +%H)
# Obtengo la fecha general para luego hacer la copia de los logs con esta misma fecha
fecha_general=$(date +"%Y-%m-%d_%H-%M")

# Luego verifico si es la hora en punto (minutos == 00)
# Y si la hora es en punto entonces limpio las Iptables, cambio los logs de apache para que no se vuelvan a bloquear las mismas ips .
if [ "$minutos" -eq "00" ]
then
    echo "Son las $hora en PUNTO (.$minutos)"
    echo "Por lo tanto, procedemos a borrar las iptables de las ips y rangos añadidos"
    echo "Ademas borramos los logs de apache, cambiandolos a un fichero nuevo llamado '$logs-eliminados-bckp.tar.gz' "
    
    # A continuacion volvemos a poner el fichero inicial de ip tables 
    sudo echo "#!/bin/bash

# Limpio todas las reglas de iptables y las de la tabla NAT
iptables -F
iptables -t nat -F

# Enmascaro las IPs de la red 192.168.0.0/24 cuando salen por enp0s3 (como un router)
iptables -t nat -A POSTROUTING -o enp0s3 -s 192.168.0.0/24 -j MASQUERADE

# Permito que el tráfico de la red 192.168.0.0/24 pase de enp0s8 a enp0s3
iptables -A FORWARD -i enp0s8 -o enp0s3 -s 192.168.0.0/24 -j ACCEPT

# Permito que el tráfico ya establecido o relacionado vuelva de enp0s3 a enp0s8
iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Pongo esta regla para que el servidor pueda hacer TIME, ya que si no pongo esta regla, al hacer pruebas, el script de mitigacion, bloquea el rango del servidor
sudo iptables -I INPUT -s 192.168.0.1 -j ACCEPT" > /usr/bin/set_iptables.sh # Podria poner "sudo $f_iptables" pero preferi poner la ruta absuluta ya que para realizar pruebas necesitaba memorizar esta ruta

    # Ejecuto estas reglas que acabo de crear.
    sudo /usr/bin/set_iptables.sh # Podria poner "sudo $f_iptables" pero preferi poner la ruta absuluta ya que para realizar pruebas necesitaba memorizar esta ruta
      
# logs="/var/log/apache2/access.log". Esta linea es para recordar la ruta a la hora de realizar pruebas.
    
    # A continuacion vacio tambien los logs de apache cambiandolos a un comprimido como ya eh explicado anteriormente.
    sudo mv $logs "$logs-eliminados-$fecha_general" && touch $logs && sudo chmod 644 $logs && sudo chown www-data:www-data $logs
    tar -rf "$logs-eliminados-bckp.tar.gz" "$logs-eliminados-$fecha_general"
    sudo rm "$logs-eliminados-$fecha_general"
    echo "Se han añadido los logs al backup correctamente"
    
    # Luego obtengo el tamaño del archivo comprimido en bytes
    tamano=$(stat -c%s "$logs-eliminados-bckp.tar.gz")

    # Si el tamaño es mayor o igual a 1GB (1073741824 bytes), elimino el comprimido para ahorrar espacio.
    if [ "$tamano" -ge 1073741824 ]
    then
        echo "El archivo comprimido '$logs-eliminados-bckp.tar.gz' ha superado 1GB."
        echo "Eliminándolo..." 
        rm "$logs-eliminados-bckp.tar.gz"
    fi


    echo "Ficheros Cambiados y eliminados correctamente."
    echo
else
    echo
    # En caso de que no sea la hora en punto, acaba el script con el siguiente mensaje.
    echo "Aun no es la hora en punto, por lo que no se vaciaran ni los logs de apache ni las iptables."
fi
echo
echo "Proceso de mitigación completado."
