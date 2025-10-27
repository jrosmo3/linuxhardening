# Hardening seguro para servidores Ubuntu/Debian

`hardening_safe.sh` es un script de endurecimiento de seguridad diseñado para entornos reales (VPS, servidores en producción, máquinas remotas sin acceso físico), con un objetivo claro:

**Mejorar la seguridad sin riesgo de perder acceso ni romper servicios.**

A diferencia de otros scripts de “hardening agresivo”, este script:
- No te bloquea el SSH.
- No corta el acceso de root sin crear primero un usuario alternativo válido.
- No aplica cambios peligrosos en red/kerneles/servicios que puedan tumbar la máquina en caliente.

---

## Objetivos principales

### 1. Mantener el acceso
- **No modifica `/etc/ssh/sshd_config`.**
- **No deshabilita el login SSH de root.**
- **No deshabilita la autenticación por contraseña.**
- **No reinicia `sshd`.**
- **No aplica políticas PAM tipo bloqueo tras X intentos.**

Traducción: aunque algo falle, sigues pudiendo entrar como antes.

### 2. Asegurar una cuenta administrativa válida
Si no existe ningún usuario con privilegios (`sudo`) aparte de `root`, el script:
- crea automáticamente un usuario admin aleatorio (`sec_xxxxxxxx`),
- le pone una contraseña robusta,
- lo mete en `sudo`,
- copia las claves SSH de `root` a ese usuario si existen,
- y guarda esos datos en `/var/log/hardening_safe/IMPORTANT_CREDENTIALS.txt` (permisos 600).

Así te garantizas que SIEMPRE hay al menos una cuenta válida con la que entrar aunque más adelante decidas desactivar el acceso SSH directo de root.

### 3. Activar defensas estándar en servidores serios
El script instala y configura herramientas de seguridad maduras y ampliamente usadas:

- **Fail2Ban**  
  Protege frente a fuerza bruta SSH. Configurado en modo “suave”: baneos cortos, sin lockout permanente.

- **auditd**  
  Registra cambios críticos (passwd, shadow, sudoers, etc.) para auditoría y forense.

- **AIDE (Advanced Intrusion Detection Environment)**  
  Genera una “foto” de integridad del sistema y programa comprobaciones diarias para detectar modificaciones no autorizadas en binarios y ficheros sensibles.

- **RKHunter**  
  Crea baseline y programa escaneos diarios buscando rootkits, binarios alterados y persistencia sospechosa.

- **sysstat / acct / lynis / debsums / needrestart**  
  Métricas de actividad, contabilidad de procesos, auditoría de seguridad y verificación de integridad de paquetes.

El resultado es: visibilidad continua y señales tempranas de compromiso, sin intervención manual constante.

### 4. Endurecer sin romper producción
El script solo aplica cambios de bajo riesgo en caliente:
- Ajusta permisos de ficheros sensibles (`/etc/shadow`, cron dirs, etc.).
- Añade banner legal de acceso/uso autorizado.
- Carga reglas de auditoría.
- Activa monitorización de integridad.
- NO toca parámetros de red que puedan cortar conectividad.
- NO deshabilita servicios como NFS, Avahi, CUPS, Samba, etc.
- NO descarga/bloquea módulos del kernel (USB, FireWire, etc.).
- NO cambia la `umask` global.
- NO restringe compiladores como `gcc` que podrían romper pipelines de build.
- NO mete reglas PAM agresivas de bloqueo de cuentas.

Así puedes ejecutar esto incluso en un servidor en producción / en remoto sin consola fuera de banda.

### 5. Hardening avanzado preparado (pero NO aplicado automáticamente)
El script genera ficheros con recomendaciones más agresivas en:

`/etc/security-hardening-recommendations/`

Ahí encontrarás:
- Reglas `sysctl` endurecidas (bloquear ICMP redirects, deshabilitar rutas de origen, limitar `ptrace`, etc.).
- Configuración SSH endurecida (deshabilitar root por SSH, exigir claves, `MaxAuthTries 3`, desactivar `X11Forwarding`, etc.).
- Lista de servicios que probablemente deberías deshabilitar si no los usas.

**Nada de eso se aplica automáticamente.**

La idea es que primero aseguras visibilidad y cuentas de emergencia, y luego (en una ventana de mantenimiento o cuando tengas acceso físico/out-of-band) aplicas los cambios más duros de forma controlada.

---

## ¿Por qué este script y no otro “hardening.sh” random?

Porque la mayoría de scripts de hardening asumen que tienes acceso físico a la máquina, consola IPMI, ILO/DRAC/KVM, etc. En un VPS en la nube eso no es verdad.

Cosas típicas que rompen producción y te dejan fuera:
- Desactivar `PermitRootLogin` sin verificar otro usuario sudo con clave.
- Poner `PasswordAuthentication no` sin haber copiado las claves al usuario nuevo.
- Reiniciar `sshd` con una config rota.
- Activar PAM lockout y bloquearte tú mismo.
- Cerrar servicios que otros equipos están usando en producción.
- Cambiar `sysctl` de red y matar el túnel VPN o el routing que te da acceso.

Este script **NO hace esas cosas automáticamente**.

---

## Flujo básico del script

1. Comprueba que estás en Debian/Ubuntu y que eres root.
2. Crea `/var/log/hardening_safe/` para logs y resúmenes.
3. Si no hay usuario sudo aparte de `root`:
   - crea uno seguro,
   - le da sudo,
   - genera credenciales y las guarda de forma controlada.
4. Instala y configura:
   - `fail2ban`, `auditd`, `aide`, `rkhunter`, `sysstat`, `acct`, `lynis`, `debsums`, etc.
5. Inicializa AIDE y RKHunter y programa tareas diarias en `cron`.
6. Añade reglas `auditd` para monitorizar cambios en ficheros críticos.
7. Ajusta permisos inseguros en ficheros y directorios sensibles.
8. Añade un banner de acceso autorizado.
9. Genera recomendaciones avanzadas en `/etc/security-hardening-recommendations/` sin aplicarlas.
10. Muestra un resumen final (incluyendo credenciales del usuario creado si aplica).

---

## Requisitos

- **Ubuntu / Debian con systemd**, por ejemplo Ubuntu 22.04 LTS o superior.
- Debes ejecutarlo como `root` (o con `sudo bash hardening_safe.sh`).
- Está pensado para servidores físicos, VPS, VM en cloud o máquina remota con SSH.
- No está pensado para contenedores Docker/LXC puros sin systemd (allí `systemctl`, `auditd`, etc. pueden no aplicar).

Importante: este script **no sustituye el parcheo del sistema**. No actualiza kernel ni corrige CVEs abiertas. Te da control, alerta temprana y buenas bases, pero sigues teniendo que actualizar.

---

## Uso

```bash
wget https://ruta-tu-repo/hardening_linux.sh -O hardening_linux.sh
chmod +x hardening_linux.sh
sudo bash ./hardening_linux.sh

##Disclaimer

Este script está diseñado para endurecer un sistema remoto sin dejarte bloqueado fuera y sin tirar servicios críticos en caliente.
Aun así:

Si tienes un firewall muy personalizado, reglas nftables complejas, software expuesto públicamente o requisitos de compliance estrictos, prueba primero en una VM clonada.

Aplica el hardening avanzado (SSH más estricto, sysctl agresivos, cierre de servicios) sólo cuando tengas una vía de acceso alternativa garantizada (consola fuera de banda, otra sesión SSH probada, etc.).

##En resumen:
Este script da una base defensiva segura y operativa. Endurece sin romper, y deja lo “peligroso pero recomendable” preparado para que lo actives tú cuando ya estés seguro de no perder acceso.
chmod +x hardening_safe.sh
sudo bash ./hardening_safe.sh
