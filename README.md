# Hardening seguro para servidores Ubuntu/Debian

`hardening_safe.sh` es un script de endurecimiento de seguridad diseñado para entornos reales (VPS, servidores en producción, máquinas remotas sin acceso físico), con un objetivo claro:

**Mejorar la seguridad sin riesgo de perder acceso ni romper servicios.**

A diferencia de otros scripts de “hardening agresivo”, este script:
- No te bloquea el SSH.
- No corta el acceso de root sin crear primero un usuario alternativo válido.
- No aplica cambios peligrosos en red/kerneles/servicios que puedan tumbar la máquina en caliente.

---

## Objetivos principales

### 1. Mantener el acceso. ESTO DEBE CAMBIARSE ACORDE A NECESIDADES OPERATIVAS.
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
  Genera una “foto” de integridad del sistema y programa comprobaciones diarias para detectar modificaciones no autorizadas en binarios
