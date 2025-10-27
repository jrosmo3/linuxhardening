#!/bin/bash
#
# SAFE SECURITY HARDENING SCRIPT (NO-LOCKOUT MODE)
#
# Garantias importantes:
#   - NO modifica /etc/ssh/sshd_config en producción
#   - NO reinicia sshd
#   - NO deshabilita el login SSH de root
#   - NO deshabilita PasswordAuthentication
#   - NO mete políticas PAM de bloqueo de cuenta
#   - NO toca sysctl activo de red / kernel
#   - NO para servicios existentes del sistema
#   - NO descarga módulos del kernel ni bloquea USB
#   - NO rompe compilación (no toca gcc/cc)
#
# Que hace:
#   - Crea usuario admin sudo adicional si eres "root-only"
#   - Copia authorized_keys de root a ese usuario si existen
#   - Guarda las credenciales en /var/log/hardening_safe/IMPORTANT_CREDENTIALS.txt
#   - Instala herramientas de auditoría e integridad (auditd, aide, rkhunter, fail2ban...)
#   - Configura Fail2Ban con reglas suaves (baneo corto, 10 intentos)
#   - Crea baseline de AIDE y RKHunter y tareas diarias en cron
#   - Refuerza permisos básicos de ficheros sensibles
#   - Muestra advertencias sobre servicios potencialmente inseguros,
#     pero NO los deshabilita automáticamente
#   - Genera RECOMENDACIONES (sysctl, SSH endurecido, etc.) en
#     /etc/security-hardening-recommendations/
#     sin aplicarlas
#
# Uso:
#   sudo bash hardening_safe.sh
#
# Requisitos:
#   - Ejecutar como root en Debian/Ubuntu
#
# Nota:
#   Este script evita bloquearte. Despues de ejecutarlo,
#   revisa /etc/security-hardening-recommendations/ para aplicar
#   endurecimiento mas agresivo a mano y cuando tengas consola fuera de banda.

set -o pipefail

############################
# 1. Comprobaciones básicas
############################

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Debes ejecutar este script como root (sudo bash $0)"
    exit 1
fi

if [[ ! -f /etc/debian_version ]] && [[ ! -f /etc/lsb-release ]]; then
    echo "[ERROR] Este script está pensado para Debian/Ubuntu"
    exit 1
fi

for cmd in apt-get dpkg systemctl sed grep tee cut sort awk hostname; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[ERROR] Falta el comando requerido: $cmd"
        exit 1
    fi
done

export DEBIAN_FRONTEND=noninteractive

START_TIME=$(date +%s)

############################
# 2. Rutas y estructura log
############################

LOG_DIR="/var/log/hardening_safe"
TOOLS_DIR="$LOG_DIR/tools"
RECOMMEND_DIR="/etc/security-hardening-recommendations"

mkdir -p "$LOG_DIR"
mkdir -p "$TOOLS_DIR"
mkdir -p "$RECOMMEND_DIR"
chmod 700 "$LOG_DIR"

LOG_FILE="$LOG_DIR/main.log"
CREDENTIALS_FILE="$LOG_DIR/IMPORTANT_CREDENTIALS.txt"
RKHUNTER_LOG="$TOOLS_DIR/rkhunter.log"
AIDE_LOG="$TOOLS_DIR/aide.log"
AUDITD_LOG="$TOOLS_DIR/auditd.log"
FAIL2BAN_LOG="$TOOLS_DIR/fail2ban.log"
SUMMARY_FILE="$LOG_DIR/summary.log"
RECOMMEND_FILE="$RECOMMEND_DIR/README.txt"

touch "$LOG_FILE" "$SUMMARY_FILE"

log_info()    { echo "[INFO] $*"    | tee -a "$LOG_FILE" ; }
log_success() { echo "[OK] $*"      | tee -a "$LOG_FILE" ; }
log_warn()    { echo "[WARN] $*"    | tee -a "$LOG_FILE" ; }
log_error()   { echo "[ERROR] $*"   | tee -a "$LOG_FILE" ; }

backup_config() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup_name="$(basename "$file").backup.$(date +%Y%m%d_%H%M%S)"
        local backup_path="$LOG_DIR/$backup_name"
        cp "$file" "$backup_path"
        log_info "Backup de $file en $backup_path"
    fi
}

########################################
# 3. Utilidades para creación de usuario
########################################

generate_password() {
    # Intenta con openssl
    if command -v openssl >/dev/null 2>&1; then
        local base="$(openssl rand -base64 16 | tr -d '/+=' | head -c 16)"
    else
        # Fallback a /dev/urandom
        local base="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c16)"
    fi

    local upper="ABCDEFGHJKLMNPQRSTUVWXYZ"
    local lower="abcdefghjkmnpqrstuvwxyz"
    local digit="23456789"
    local special="!@#%^&*_+:,.-"

    local u=${upper:RANDOM % ${#upper}:1}
    local l=${lower:RANDOM % ${#lower}:1}
    local d=${digit:RANDOM % ${#digit}:1}
    local s=${special:RANDOM % ${#special}:1}

    echo "${base}${u}${l}${d}${s}" | head -c20
}

generate_random_username() {
    local suffix
    suffix=$(openssl rand -hex 4 2>/dev/null || tr -dc 'a-f0-9' </dev/urandom | head -c8)
    echo "sec_${suffix}"
}

########################################
# 4. Crear usuario sudo alternativo seguro
########################################

log_info "Comprobando si existe ya algún usuario con sudo distinto de root..."

existing_sudo_users=$(
    {
        getent group sudo
        getent group admin
        getent group wheel
    } 2>/dev/null \
    | cut -d: -f4 \
    | tr ',' '\n' \
    | grep -v '^root$' \
    | grep -v '^$' \
    | sort -u
)

NEW_USER_CREATED="false"
NEW_USER=""
USER_PASSWORD=""

if [[ -z "$existing_sudo_users" ]]; then
    log_warn "No se ha encontrado ningún usuario sudo distinto de root. Se va a crear uno de respaldo."

    NEW_USER=$(generate_random_username)
    USER_PASSWORD=$(generate_password)

    # Crear usuario con shell bash y home
    if useradd -m -s /bin/bash "$NEW_USER" 2>>"$LOG_FILE"; then
        log_success "Usuario $NEW_USER creado"
    else
        log_error "No se pudo crear el usuario $NEW_USER"
        exit 1
    fi

    # Establecer contraseña
    if echo "$NEW_USER:$USER_PASSWORD" | chpasswd 2>>"$LOG_FILE"; then
        log_success "Contraseña asignada al usuario $NEW_USER"
    else
        log_error "No se pudo asignar la contraseña a $NEW_USER"
        exit 1
    fi

    # Añadir a sudo (o wheel/admin si aplica)
    if getent group sudo >/dev/null 2>&1; then
        usermod -aG sudo "$NEW_USER" 2>>"$LOG_FILE"
    elif getent group admin >/dev/null 2>&1; then
        usermod -aG admin "$NEW_USER" 2>>"$LOG_FILE"
    elif getent group wheel >/dev/null 2>&1; then
        usermod -aG wheel "$NEW_USER" 2>>"$LOG_FILE"
    fi

    # Política de expiración de contraseña razonable
    chage -M 90 -m 10 -W 7 "$NEW_USER" 2>>"$LOG_FILE" || true

    # Copiar authorized_keys de root si existen (mejora operatividad, no quita acceso)
    if [[ -f /root/.ssh/authorized_keys ]]; then
        log_info "Copiando claves SSH de root a $NEW_USER..."
        USER_HOME=$(getent passwd "$NEW_USER" | cut -d: -f6)
        mkdir -p "$USER_HOME/.ssh"
        cp /root/.ssh/authorized_keys "$USER_HOME/.ssh/authorized_keys"
        chown -R "$NEW_USER:$NEW_USER" "$USER_HOME/.ssh"
        chmod 700 "$USER_HOME/.ssh"
        chmod 600 "$USER_HOME/.ssh/authorized_keys"
        log_success "Claves SSH copiadas"
    else
        log_warn "Root no tiene authorized_keys. El usuario $NEW_USER usará contraseña por ahora."
    fi

    # Guardar credenciales en archivo seguro
    IP_ADDR=$(hostname -I | awk '{print $1}')
    cat > "$CREDENTIALS_FILE" << EOF
########################################################################
 CREDENCIALES ADMIN DE RESPALDO (GUARDAR EN SEGURO Y LUEGO BORRAR)
########################################################################

 Hostname: $(hostname)
 IP:       $IP_ADDR

 Usuario administrador creado automáticamente:
   Usuario : $NEW_USER
   Password: $USER_PASSWORD

 Este usuario está en el grupo sudo (o equivalente) y puede usar sudo
 para elevar privilegios después de iniciar sesión por SSH.

 IMPORTANTE:
   - Prueba el acceso SSH con este usuario ANTES de cerrar tu sesión root.
   - Asegúrate de poder hacer "sudo whoami" una vez conectado.
   - Luego mueve este fichero fuera del servidor y bórralo.

 Ruta de este fichero:
   $CREDENTIALS_FILE

Fecha: $(date)
########################################################################
EOF
    chmod 600 "$CREDENTIALS_FILE"
    log_warn "SE HAN ESCRITO CREDENCIALES en $CREDENTIALS_FILE"
    NEW_USER_CREATED="true"
else
    log_success "Usuarios sudo ya existentes: $existing_sudo_users"
    log_info "No se crea usuario nuevo, no se tocan accesos SSH."
fi

########################################
# 5. Preconfigurar APT y funciones helper
########################################

# Evitar prompts de Postfix si algún paquete lo arrastra
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
debconf-set-selections <<< "postfix postfix/mailname string $(hostname -f)"

install_package() {
    local package="$1"
    log_info "Instalando/verificando paquete $package..."
    if dpkg -l | grep -qw "$package" 2>/dev/null; then
        log_info "$package ya está instalado."
        return 0
    fi

    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        "$package" >> "$LOG_FILE" 2>&1; then
        log_success "$package instalado"
        return 0
    else
        # Si apt devolvió error pero el paquete aparece instalado, aceptamos
        if dpkg -l | grep -qw "$package" 2>/dev/null; then
            log_success "$package instalado (verificado tras error apt)"
            return 0
        fi
        log_warn "No se pudo instalar $package (continuo igual)"
        return 1
    fi
}

apt-get update -qq >> "$LOG_FILE" 2>&1 || log_warn "apt-get update devolvió error, continúo"

PACKAGES=(
    "fail2ban"
    "auditd"
    "aide"
    "rkhunter"
    "acct"
    "sysstat"
    "lynis"
    "libpam-pwquality"
    "needrestart"
    "debsums"
    "apt-listchanges"
    "apt-show-versions"
    "bsd-mailx"
)

for pkg in "${PACKAGES[@]}"; do
    install_package "$pkg"
done

########################################
# 6. Ajuste seguro de permisos críticos
########################################
log_info "Revisando permisos mínimos en ficheros sensibles"

# Esto NO rompe operatividad. Solo endurece lectura a usuarios no root.
[[ -f /etc/passwd    ]] && chmod 644 /etc/passwd    2>/dev/null || true
[[ -f /etc/group     ]] && chmod 644 /etc/group     2>/dev/null || true
[[ -f /etc/shadow    ]] && chmod 640 /etc/shadow    2>/dev/null || true
[[ -f /etc/gshadow   ]] && chmod 640 /etc/gshadow   2>/dev/null || true
[[ -f /etc/crontab   ]] && chmod 600 /etc/crontab   2>/dev/null || true

for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [[ -d "$crondir" ]] && chmod 700 "$crondir" 2>/dev/null || true
done

log_success "Permisos básicos verificados/endurecidos sin impacto en acceso"

########################################
# 7. Configuración suave de Fail2Ban
########################################
log_info "Configurando Fail2Ban (suave, sin riesgo de lockout permanente)"

backup_config "/etc/fail2ban/jail.local"

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Baneo corto (5 minutos)
bantime = 300
findtime = 600
# Se permiten hasta 10 intentos fallidos antes de banear
maxretry = 10

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF

# Iniciar/activar Fail2Ban
if command -v systemctl >/dev/null 2>&1; then
    systemctl enable fail2ban >> "$FAIL2BAN_LOG" 2>&1 || true
    systemctl restart fail2ban >> "$FAIL2BAN_LOG" 2>&1 || \
    systemctl start fail2ban >> "$FAIL2BAN_LOG" 2>&1 || true
else
    service fail2ban restart >> "$FAIL2BAN_LOG" 2>&1 || service fail2ban start >> "$FAIL2BAN_LOG" 2>&1 || true
fi

if systemctl is-active --quiet fail2ban 2>/dev/null; then
    log_success "Fail2Ban activo protegiendo SSH (baneo temporal, sin bloqueo definitivo)"
else
    log_warn "Fail2Ban no parece activo, revisa $FAIL2BAN_LOG si te interesa"
fi

########################################
# 8. Configurar auditd (monitorización)
########################################
log_info "Configurando auditd"

backup_config "/etc/audit/rules.d/hardening.rules"

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Cambios en cuentas/grupos
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/gshadow -p wa -k gshadow_changes

# Cambios en sudoers
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Cambios en configuración de SSH
-w /etc/ssh/ -p wa -k ssh_config_changes

# Cambios en logs
-w /var/log/ -p wa -k log_changes
EOF

if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >> "$AUDITD_LOG" 2>&1 || log_warn "augenrules --load tuvo advertencias"
fi

# Reiniciar/arrancar auditd
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd >> "$AUDITD_LOG" 2>&1 || systemctl start auditd >> "$AUDITD_LOG" 2>&1 || true
else
    service auditd restart >> "$AUDITD_LOG" 2>&1 || service auditd start >> "$AUDITD_LOG" 2>&1 || true
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    log_success "auditd activo (registrará cambios críticos)"
else
    log_warn "auditd no parece activo, revisa $AUDITD_LOG"
fi

########################################
# 9. Inicializar AIDE (integridad de ficheros)
########################################
log_info "Inicializando AIDE (baseline de integridad del sistema)"

# backup db previa si existe
if [[ -f /var/lib/aide/aide.db ]]; then
    cp /var/lib/aide/aide.db "$LOG_DIR/aide.db.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    rm -f /var/lib/aide/aide.db
fi
rm -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz 2>/dev/null || true

if timeout 600 aideinit >> "$AIDE_LOG" 2>&1; then
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
        gunzip /var/lib/aide/aide.db.new.gz
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    log_success "Baseline AIDE creada en /var/lib/aide/aide.db"
else
    log_warn "AIDE tardó demasiado o falló (revisa $AIDE_LOG). Puedes ejecutar 'aideinit' manualmente más tarde."
fi

# Cron diario para chequeo AIDE (envía mail local a root; si no hay MTA, no rompe nada)
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check 2>&1 | mail -s "AIDE Daily Report $(hostname)" root
EOF
chmod +x /etc/cron.daily/aide-check

########################################
# 10. Inicializar RKHunter (rootkits)
########################################
log_info "Inicializando RKHunter (detección de rootkits)"

# Configuración básica de rkhunter para modo cron silencioso
if [[ -f /etc/default/rkhunter ]]; then
    backup_config "/etc/default/rkhunter"
    sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter 2>/dev/null || true
    sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="true"/' /etc/default/rkhunter 2>/dev/null || true
    sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="yes"/' /etc/default/rkhunter 2>/dev/null || true
fi

# Generar baseline de propiedades de ficheros
timeout 300 rkhunter --propupd --no-colors >> "$RKHUNTER_LOG" 2>&1 || true

# Primer escaneo rápido (solo warnings)
timeout 600 rkhunter --check --skip-keypress --no-colors --report-warnings-only >> "$RKHUNTER_LOG" 2>&1 || true

# Cron diario para rkhunter
cat > /etc/cron.daily/rkhunter-safe << 'EOF'
#!/bin/bash
/usr/bin/rkhunter --cronjob --report-warnings-only --quiet 2>&1 | mail -s "RKHunter Daily Report $(hostname)" root
EOF
chmod +x /etc/cron.daily/rkhunter-safe

log_success "RKHunter configurado con baseline inicial y cron diario"

########################################
# 11. Banner legal de login (con backup)
########################################
log_info "Configurando banner legal (SSH / consola). Se hace backup antes."

backup_config "/etc/issue"
backup_config "/etc/issue.net"

cat > /etc/issue << 'EOF'
***********************************************************************
                ACCESO AUTORIZADO EXCLUSIVAMENTE
 El uso no autorizado de este sistema está prohibido y puede ser
 monitorizado y comunicado. Si no estás autorizado, desconecta.
***********************************************************************
EOF

cp /etc/issue /etc/issue.net 2>/dev/null || true
log_success "Banner legal aplicado (SSH mostrará /etc/issue.net)."

########################################
# 12. Recomendaciones NO aplicadas
########################################
log_info "Generando recomendaciones de endurecimiento (NO aplicadas automáticamente)"

cat > "$RECOMMEND_DIR/sysctl_recommend.conf" << 'EOF'
# Recomendaciones de red / kernel (NO cargadas automáticamente)
# Revísalas MANUALMENTE antes de habilitarlas.
# Ejemplo de activación: mover este fichero a /etc/sysctl.d/ y luego 'sysctl --system'

net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

net.ipv4.tcp_syncookies = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0

kernel.core_pattern = /dev/null
kernel.core_uses_pid = 1

kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
EOF

cat > "$RECOMMEND_DIR/ssh_hardening_suggestion.txt" << 'EOF'
Estas son medidas típicas de endurecimiento SSH.
NO se han aplicado automáticamente para evitar lockout.

- Editar /etc/ssh/sshd_config y después TESTEAR ANTES DE CORTAR SESIÓN:
    Protocol 2
    PermitRootLogin no
    PasswordAuthentication no
    PermitEmptyPasswords no
    MaxAuthTries 3
    X11Forwarding no
    AllowAgentForwarding no
    ClientAliveInterval 300
    ClientAliveCountMax 2
    KbdInteractiveAuthentication no
    ChallengeResponseAuthentication no

- Después de editar, validar:
    sshd -t
  y reiniciar sshd sólo si la validación es OK.

- OBLIGATORIO: asegurarse de que al menos UN usuario sudo distinto de root
  tiene acceso por clave pública funcional antes de deshabilitar el root
  o deshabilitar PasswordAuthentication.
EOF

# Chequear servicios "ruidosos" que en hardening estricto se suelen apagar:
POSSIBLE_RISK_SERVICES=(avahi-daemon cups rpcbind nfs-server nfs-kernel-server snmpd rsync)
{
    echo "Servicios detectados que podrías querer deshabilitar manualmente si no los usas (revisión manual):"
    for svc in "${POSSIBLE_RISK_SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "  - $svc está ACTIVO"
        fi
    done
    echo ""
    echo "Nada se ha deshabilitado automáticamente para no romper operativa."
} > "$RECOMMEND_DIR/services_review.txt"

cat > "$RECOMMEND_FILE" << 'EOF'
Este directorio contiene endurecimientos RECOMENDADOS que NO se han aplicado
automáticamente para que el servidor no pierda conectividad ni servicios.

1. sysctl_recommend.conf
   - Parámetros de red/kernel seguros.
   - Aplícalos sólo cuando tengas acceso consola fuera de banda.

2. ssh_hardening_suggestion.txt
   - Ajustes SSH típicos (deshabilitar root por SSH, sólo llaves, etc.).
   - Debes validar "sshd -t" antes de reiniciar sshd y probar acceso
     con un usuario sudo distinto de root.

3. services_review.txt
   - Lista servicios de broadcast/red (avahi, cups, rpcbind, NFS, etc.)
     que sueles querer parar en producción. Aquí SOLO se listan, no se paran.

Esta aproximación evita dejarte fuera del sistema.
EOF

log_success "Recomendaciones generadas en $RECOMMEND_DIR (sin aplicar)"

########################################
# 13. Resumen final
########################################
END_TIME=$(date +%s)
EXECUTION_TIME=$((END_TIME - START_TIME))
EXEC_MIN=$((EXECUTION_TIME / 60))
EXEC_SEC=$((EXECUTION_TIME % 60))

{
    echo "============================================================"
    echo " HARDENING SEGURO COMPLETADO"
    echo "============================================================"
    echo "Fecha: $(date)"
    echo "Host : $(hostname)"
    echo "Tiempo de ejecución: ${EXEC_MIN}m ${EXEC_SEC}s"
    echo ""

    if [[ "$NEW_USER_CREATED" == "true" ]]; then
        echo "Se creó un usuario sudo de respaldo:"
        echo "  Usuario : $NEW_USER"
        echo "  Password: $USER_PASSWORD"
        echo "  Detalles completos en: $CREDENTIALS_FILE"
        echo ""
        echo "IMPORTANTE:"
        echo " - Prueba SSH con ese usuario ANTES de cerrar tu sesión root."
        echo " - Haz 'sudo whoami' tras iniciar sesión con él."
        echo " - Copia $CREDENTIALS_FILE fuera y bórralo después."
        echo ""
    else
        echo "Ya existían usuarios sudo distintos de root:"
        echo "  $existing_sudo_users"
        echo ""
    fi

    echo "Servicios habilitados:"
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "  - Fail2Ban (modo suave, baneo 5 min tras 10 intentos)"
    else
        echo "  - Fail2Ban no activo, revisa $FAIL2BAN_LOG si te interesa"
    fi

    if systemctl is-active --quiet auditd 2>/dev/null; then
        echo "  - auditd (monitoriza cambios críticos)"
    else
        echo "  - auditd no activo, revisa $AUDITD_LOG"
    fi

    echo "  - AIDE baseline creada (cron diario en /etc/cron.daily/aide-check)"
    echo "  - RKHunter baseline creada (cron diario en /etc/cron.daily/rkhunter-safe)"
    echo "  - sysstat/acct instalados para métricas y contabilidad de procesos"

    echo ""
    echo "NO se han tocado estas cosas (por tu seguridad):"
    echo "  - NO se ha modificado /etc/ssh/sshd_config en vivo"
    echo "  - NO se ha reiniciado sshd"
    echo "  - NO se ha deshabilitado root por SSH"
    echo "  - NO se ha deshabilitado PasswordAuthentication"
    echo "  - NO se han aplicado sysctl que puedan romper red/rutas"
    echo "  - NO se han parado servicios de red (NFS, CUPS, Avahi...)"
    echo "  - NO se han bloqueado módulos kernel (USB/storage/BPF/etc.)"
    echo "  - NO se ha tocado PAM para lockouts"
    echo "  - NO se ha limitado gcc/compiladores"
    echo "  - NO se ha cambiado umask global"
    echo ""

    echo "Revisa las recomendaciones manuales en:"
    echo "  $RECOMMEND_DIR/"
    echo ""
    echo "Logs detallados:"
    echo "  $LOG_FILE"
    echo "  $SUMMARY_FILE"
    echo "  $TOOLS_DIR/"
    echo ""
    echo "============================================================"
} | tee -a "$SUMMARY_FILE"

log_success "Hardening seguro finalizado."
exit 0
