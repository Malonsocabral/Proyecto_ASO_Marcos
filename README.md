
# Proyecto ASO - Mitigación de Ataques DDoS - Marcos A

## Descripción
Este proyecto consiste en la implementación de un sistema automatizado para detectar y bloquear IPs maliciosas que puedan estar realizando ataques DDoS. Se basa en la instalación y configuración de un servidor Ubuntu con Apache, junto con un script en Bash que monitoriza y mitiga ataques.

## Tecnologías Utilizadas
- **Ubuntu Server 22.04.5**: Sistema operativo base.
- **Apache2**: Servidor web para pruebas de carga.
- **Bash Scripting**: Desarrollo del script de mitigación.
- **Kali Linux**: Máquina atacante para simular ataques.
- **Crontab**: Automatización del script de mitigación.
- **iptables**: Firewall para bloquear tráfico sospechoso.

## Instalación
### 1. Montaje de Ubuntu Server
- Descargar Ubuntu Server 22.04.5 desde [aquí](https://ubuntu.com/download/server).
- Configurar red con dos interfaces: NAT y Red Interna.
- Ejecutar el script de configuración:
  ```bash
  wget https://raw.githubusercontent.com/Malonsocabral/Proyecto_ASO_Marcos/main/010_Montage-UbuntuServer.sh
  chmod +x 010_Montage-UbuntuServer.sh
  sudo ./010_Montage-UbuntuServer.sh
  ```

### 2. Instalación de Apache2
- Instalar Apache2 con:
  ```bash
  sudo apt install apache2
  ```
- Reiniciar el servicio:
  ```bash
  sudo service apache2 restart
  ```

### 3. Configuración de Email
- Descargar y ejecutar el script de configuración:
  ```bash
  wget https://raw.githubusercontent.com/Malonsocabral/Proyecto_ASO_Marcos/main/020_mail-conf.sh
  chmod +x 020_mail-conf.sh
  sudo ./020_mail-conf.sh
  ```
- Configurar una contraseña de aplicación en Google si es necesario.

### 4. Implementación del Script de Mitigación
- Descargar y dar permisos de ejecución al script:
  ```bash
  wget https://raw.githubusercontent.com/Malonsocabral/Proyecto_ASO_Marcos/main/030_Script_Mitigacion-DDOS_Marcos.sh
  chmod +x 030_Script_Mitigacion-DDOS_Marcos.sh
  ```

### 5. Instalación de Kali Linux
- Descargar la ISO de Kali desde [aquí](https://www.kali.org/get-kali/#kali-virtual-machines).
- Configurar la red en modo "Red Interna".
- Instalar herramientas de prueba:
  ```bash
  sudo apt install apache2-utils hping3
  ```

## Simulación de Ataque y Mitigación
1. Ejecutar un ataque con Apache Benchmark:
   ```bash
   ab -n 5000 -c 500 http://192.168.0.1/
   ```
2. Ejecutar un ataque con hping3:
   ```bash
   sudo hping3 -S -p 80 --flood --rand-source 192.168.0.1
   ```
3. Activar el script de mitigación:
   ```bash
   sudo ./030_Script_Mitigacion-DDOS_Marcos.sh
   ```
4. Comprobar la mejora en tiempos de respuesta con:
   ```bash
   time curl -s -o /dev/null http://192.168.0.1/
   ```

## Automatización con Crontab
Para ejecutar el script de mitigación cada minuto:
```bash
sudo crontab -e
```
Añadir la siguiente línea:
```bash
* * * * * /ruta/al/script/030_Script_Mitigacion-DDOS_Marcos.sh
```

## Comparación con Aplicaciones Similares
| Característica       | Mi Script | Fail2Ban | Cloudflare |
|----------------------|----------|----------|------------|
| Detección           | Umbral fijo y patrones simples | Regex y múltiples servicios | Análisis avanzado y CDN |
| Bloqueo de IPs      | iptables (IPs y rangos) | Bloqueo temporal | Protección a nivel global |
| Escalabilidad       | Servidores pequeños | Servidores medianos | Empresas y alto tráfico |
| Monitoreo en tiempo real | No | Sí | Sí |

## Posibles Mejoras
- Integración con herramientas como **Wireshark** o **Suricata**.
- Implementación de **Machine Learning** para detección de ataques.
- Uso de **ModSecurity** para reglas avanzadas de seguridad.
- Implementación de un sistema de monitoreo con **Prometheus**.

## Contacto
Proyecto desarrollado por **Marcos Alonso Cabral**.
Repositorio en GitHub: [Proyecto_ASO](https://github.com/Malonsocabral/Proyecto_ASO_Marcos)
