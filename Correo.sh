#!/bin/bash

# Verificar si el usuario tiene permisos de superusuario
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script como superusuario (root)."
  exit 1
fi

# Solicitar correo electrónico y contraseña del usuario
read -p "Introduce tu correo electrónico (ejemplo@gmail.com): " email
read -sp "Introduce tu contraseña de aplicación (o contraseña de Gmail): " password
echo ""

# Verificar si se proporcionaron correo y contraseña
if [ -z "$email" ] || [ -z "$password" ]; then
  echo "Error: Debes proporcionar un correo electrónico y una contraseña."
  exit 1
fi

# Instalar mailutils y ssmtp
echo "Instalando mailutils y ssmtp..."
apt-get update
apt-get install -y mailutils ssmtp

# Configurar ssmtp
echo "Configurando ssmtp..."
echo "root=$email
mailhub=smtp.gmail.com:587
AuthUser=$email
AuthPass=$password
UseTLS=YES
UseSTARTTLS=YES
hostname=$(hostname)
FromLineOverride=YES" > /etc/ssmtp/ssmtp.conf

# Configurar el archivo revaliases
echo "Configurando revaliases..."
echo "root:$email:smtp.gmail.com:587" > /etc/ssmtp/revaliases

# Probar el envío de un correo
echo "Enviando correo de prueba a $email..."
echo "Este es un correo de prueba desde $(hostname)." | mail -s "Correo de prueba" "$email"

# Verificar si el correo se envió correctamente
if [ $? -eq 0 ]; then
  echo "Correo de prueba enviado correctamente a $email."
else
  echo "Error: No se pudo enviar el correo de prueba. Revisa la configuración de ssmtp."
  exit 1
fi

echo "Configuración completada. Ahora puedes enviar correos desde este servidor."
