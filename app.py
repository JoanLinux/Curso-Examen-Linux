import csv
import io
import copy
import json
import os
import random
import re
import sqlite3
import statistics
import time
import unicodedata
import uuid
from collections import defaultdict
from hmac import compare_digest
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from flask import Flask, Response, jsonify, redirect, render_template, request, url_for
from ml_insights import build_ml_risk

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "curso_linux.db"

DEFAULT_STUDENTS = [
    "Ana Torres",
    "Brenda Lopez",
    "Carlos Ruiz",
    "Daniela Gomez",
    "Eduardo Flores",
    "Fernanda Perez",
    "Hector Ramos",
    "Ivonne Castro",
    "Jorge Medina",
    "Karla Sanchez",
    "Luis Navarro",
    "Mariana Ortega",
]

GOOGLE_SHEET_CSV_URL = os.environ.get(
    "CURSO_LINUX_STUDENTS_CSV_URL",
    "https://docs.google.com/spreadsheets/d/1aQS5EIPsvDdke4E2MeYrPRSurFZ2KURdJjQNJmAR2zA/export?format=csv&gid=0",
)
STUDENTS_CACHE_TTL_SECONDS = int(os.environ.get("CURSO_LINUX_STUDENTS_CACHE_TTL", "300"))
PROTECTED_DELETE_PASSWORD = os.environ.get("CURSO_LINUX_PROTECTED_DELETE_PASSWORD", "ikusi2025")

_STUDENTS_CACHE = {
    "loaded_at": 0.0,
    "students": DEFAULT_STUDENTS.copy(),
}

DISTRO_ROTATION = [
    {"name": "Ubuntu", "image": "ubuntu.svg"},
    {"name": "Debian", "image": "debian.svg"},
    {"name": "Kali Linux", "image": "kali.svg"},
    {"name": "Linux Mint", "image": "mint.svg"},
    {"name": "Arch Linux", "image": "arch.svg"},
    {"name": "Fedora", "image": "fedora.svg"},
    {"name": "openSUSE", "image": "opensuse.svg"},
    {"name": "CentOS", "image": "centos.svg"},
    {"name": "Manjaro", "image": "manjaro.svg"},
    {"name": "Gentoo", "image": "gentoo.svg"},
    {"name": "Slackware", "image": "slackware.svg"},
    {"name": "MX Linux", "image": "mxlinux.svg"},
    {"name": "Alpine Linux", "image": "alpine.svg"},
    {"name": "Rocky Linux", "image": "rocky.svg"},
    {"name": "AlmaLinux", "image": "almalinux.svg"},
    {"name": "Parrot OS", "image": "parrotos.svg"},
    {"name": "Red Hat Enterprise Linux", "image": "redhat.svg"},
    {"name": "SUSE Linux Enterprise", "image": "suse.svg"},
    {"name": "NixOS", "image": "nixos.svg"},
    {"name": "Void Linux", "image": "voidlinux.svg"},
    {"name": "EndeavourOS", "image": "endeavouros.svg"},
    {"name": "Zorin OS", "image": "zorin.svg"},
    {"name": "elementary OS", "image": "elementary.svg"},
    {"name": "Pop!_OS", "image": "popos.svg"},
    {"name": "Kubuntu", "image": "kubuntu.svg"},
    {"name": "Lubuntu", "image": "lubuntu.svg"},
    {"name": "Xubuntu", "image": "xubuntu.svg"},
    {"name": "Ubuntu MATE", "image": "ubuntumate.svg"},
    {"name": "Tails", "image": "tails.svg"},
    {"name": "Qubes OS", "image": "qubesos.svg"},
    {"name": "Devuan", "image": "devuan.svg"},
    {"name": "Solus", "image": "solus.svg"},
    {"name": "KDE neon", "image": "kdeneon.svg"},
    {"name": "Deepin", "image": "deepin.svg"},
    {"name": "Slint", "image": "slint.svg"},
    {"name": "Mandrake Linux", "image": "mandrake.svg"},
    {"name": "Mandriva", "image": "mandriva.svg"},
    {"name": "Caldera OpenLinux", "image": "caldera.svg"},
]

DEFAULT_TOPIC = "General Linux"


def topic_for_item_id(item_id: str) -> str:
    iid = (item_id or "").lower()
    if iid.startswith("shell_") or iid.startswith("cmd_"):
        if "cups" in iid:
            return "Servicios de impresion (CUPS)"
        if "fw_" in iid or "firewall" in iid:
            return "Firewall y seguridad"
        if "chmod" in iid or "chown" in iid:
            return "Permisos y propiedad"
        if "samba" in iid or "smbpasswd" in iid:
            return "Permisos y propiedad"
        if "cron" in iid:
            return "Tareas programadas (cron)"
        if "pkg_" in iid or "apt" in iid or "dpkg" in iid:
            return "Gestion de paquetes"
        if "net_" in iid or iid.endswith("ss_listen") or "ss_" in iid:
            return "Redes"
        if "proc_" in iid or "ps_" in iid or "top" in iid or "htop" in iid or "kill" in iid or "pkill" in iid:
            return "Procesos y rendimiento"
        if "journal" in iid or "log" in iid or "grep" in iid or "tail" in iid or "head" in iid:
            return "Logs y diagnostico"
        if "tar" in iid or "respaldo" in iid or "rsync" in iid:
            return "Respaldo y restauracion"
        if "find" in iid or "cat_" in iid or "mv_" in iid or "df_" in iid or "du_" in iid:
            return "Archivos y filesystem"
        if "shadow" in iid or "whoami" in iid or "last" in iid or "user_" in iid or "keyring" in iid or "priv_" in iid:
            return "Usuarios y cuentas"
        return "Comandos de shell"
    if iid.startswith("hist_"):
        return "Historia y arquitectura Linux"
    if iid.startswith("img_"):
        return "Analisis visual (top/htop)"
    if iid.startswith("s3_"):
        return "Operacion y metodologia"
    return DEFAULT_TOPIC


def command_base(cmd: str) -> str:
    c = (cmd or "").strip()
    if not c:
        return ""
    p = c.split()
    if not p:
        return ""
    if p[0] == "sudo" and len(p) > 1:
        return p[1].lower()
    return p[0].lower()


def classify_error_severity(item_type: str, item_id: str, user_answer: str, expected: str, command_trace: Optional[List[str]] = None) -> str:
    if item_type != "shell":
        return "conceptual"
    exp_base = command_base(expected)
    if not exp_base:
        return "conceptual"
    attempts = [str(x).strip() for x in (command_trace or []) if str(x).strip()]
    if user_answer:
        attempts.append(user_answer)
    for a in attempts:
        if command_base(a) == exp_base:
            return "sintaxis"
    return "conceptual"


def student_key_for_cycle(student_name: str, student_email: str) -> str:
    email = (student_email or "").strip().lower()
    if email:
        return f"email:{email}"
    return f"name:{normalize_key(student_name or '').strip()}"

COMMAND_QUESTIONS = [
    {
        "id": "cmd_hidden_files",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar archivos ocultos del directorio actual.",
        "choices": [
            "ls -la",
            "ls",
            "find . -type d",
            "pwd",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_head_passwd",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para mostrar las primeras 10 lineas de /etc/passwd.",
        "choices": [
            "tail -n 10 /etc/passwd",
            "head -n 10 /etc/passwd",
            "cat /etc/passwd | wc -l",
            "grep passwd /etc",
        ],
        "correct": 1,
    },
    {
        "id": "cmd_tail_syslog",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver las ultimas 20 lineas de /var/log/syslog.",
        "choices": ["tail -n 20 /var/log/syslog", "head -n 20 /var/log/syslog", "cat /var/log/syslog", "grep 20 /var/log/syslog"],
        "correct": 0,
    },
    {
        "id": "cmd_rm_safe",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para borrar archivo_tmp.log pidiendo confirmacion.",
        "choices": ["rm -f archivo_tmp.log", "rm -i archivo_tmp.log", "del archivo_tmp.log", "mv archivo_tmp.log /tmp"],
        "correct": 1,
    },
    {
        "id": "cmd_ps_zombie",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar posibles procesos zombie usando ps.",
        "choices": ["ps aux | grep Z", "top -z", "grep zombie /proc", "jobs -l"],
        "correct": 0,
    },
    {
        "id": "cmd_systemctl_restart",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para reiniciar apache2 en Ubuntu/Debian.",
        "choices": ["systemctl restart apache2", "service apache2 stop", "apache2 --restart", "restart apache2 --now"],
        "correct": 0,
    },
    {
        "id": "cmd_journalctl_last",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver las ultimas 50 lineas del log de apache2 con journalctl.",
        "choices": [
            "journalctl -u apache2 -n 50",
            "journalctl apache2 tail 50",
            "tail -u apache2 -n 50",
            "journalctl /var/log/apache2 -n 50",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_find_hidden",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para encontrar archivos ocultos dentro de /home/alumno.",
        "choices": [
            "find /home/alumno -type f -name '.*'",
            "ls -a /home/alumno | grep .",
            "find hidden /home/alumno",
            "grep -r '^\\.' /home/alumno",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_du_sort",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver las 5 carpetas que mas espacio consumen en /var.",
        "choices": [
            "du -h /var | sort -hr | head -n 5",
            "df -h /var | head -n 5",
            "du -s /var | tail -n 5",
            "ls -lh /var | sort -hr | head -n 5",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_chmod_chown",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para dejar script.sh ejecutable solo por propietario y cambiar propietario a alumno:soporte.",
        "choices": [
            "chown alumno:soporte script.sh && chmod 700 script.sh",
            "chmod 777 script.sh && chown root:root script.sh",
            "chown soporte script.sh && chmod +x",
            "chmod 700 && chown alumno script.sh",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_ss_port",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar puertos TCP en escucha con PID/proceso.",
        "choices": ["ss -tulnp", "netstat -t", "ip a", "ss -uln"],
        "correct": 0,
    },
    {
        "id": "cmd_grep_tail_error",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para filtrar 'error' en syslog y ver las ultimas 20 coincidencias.",
        "choices": [
            "grep -i error /var/log/syslog | tail -n 20",
            "tail -n 20 /var/log/syslog | grep -v error",
            "grep error -n 20 /var/log/syslog",
            "cat /var/log/syslog error | tail",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_tar_backup",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para comprimir /etc en respaldo.tar.gz.",
        "choices": [
            "tar -czf respaldo.tar.gz /etc",
            "tar -xzf respaldo.tar.gz /etc",
            "zip respaldo.tar.gz /etc",
            "gzip /etc > respaldo.tar.gz",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_cups_status",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver el estado del servicio CUPS en sistemas con systemd.",
        "choices": ["systemctl status cups", "service printer status", "cups --status", "lpstat --service"],
        "correct": 0,
    },
    {
        "id": "cmd_cups_restart",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para reiniciar CUPS.",
        "choices": ["systemctl restart cups", "cupsctl restart", "service cups stop", "lpadmin --restart cups"],
        "correct": 0,
    },
    {
        "id": "cmd_cups_printers",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar impresoras configuradas en CUPS.",
        "choices": ["lpstat -p", "cupsd -l", "lpadmin -p", "lpr -p"],
        "correct": 0,
    },
    {
        "id": "cmd_cups_jobs",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para mostrar la cola de trabajos de impresion en CUPS.",
        "choices": ["lpstat -o", "lpstat -p", "lpadmin -x", "cancel -a printers"],
        "correct": 0,
    },
    {
        "id": "cmd_echo_shell",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para mostrar el shell actual del usuario.",
        "choices": ["echo $SHELL", "whoami", "pwd", "uname -a"],
        "correct": 0,
    },
    {
        "id": "cmd_apt_search_htop",
        "type": "mcq",
        "prompt": "En el flujo de instalacion de paquetes, cual comando busca el paquete htop?",
        "choices": ["apt search htop", "dpkg -l | grep htop", "apt install htop -y", "apt update"],
        "correct": 0,
    },
    {
        "id": "cmd_dpkg_verify_htop",
        "type": "mcq",
        "prompt": "Cual comando verifica si htop quedo instalado, segun la presentacion?",
        "choices": ["dpkg -l | grep htop", "apt search htop", "htop --install-check", "service htop status"],
        "correct": 0,
    },
    {
        "id": "cmd_pkg_update_lists",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para actualizar el indice/lista de paquetes en Debian/Ubuntu.",
        "choices": ["apt update", "apt upgrade", "dpkg --configure -a", "apt-cache policy"],
        "correct": 0,
    },
    {
        "id": "cmd_pkg_install_curl",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para instalar curl usando apt.",
        "choices": ["apt install curl -y", "apt remove curl", "dpkg -r curl", "curl --install"],
        "correct": 0,
    },
    {
        "id": "cmd_pkg_remove_htop",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para desinstalar htop SIN borrar archivos de configuracion.",
        "choices": ["apt remove htop -y", "apt purge htop -y", "dpkg --purge htop", "apt autoremove --purge htop -y"],
        "correct": 0,
    },
    {
        "id": "cmd_priv_user_vs_sudo",
        "type": "mcq",
        "prompt": "Cual afirmacion describe mejor la diferencia entre usuario normal y sudo?",
        "choices": [
            "El usuario normal tiene permisos limitados; sudo ejecuta temporalmente con privilegios de administrador.",
            "Sudo solo sirve para cambiar de directorio.",
            "No hay diferencia real en Ubuntu.",
            "Sudo solo se usa para comandos de red.",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_keyring_reset_path",
        "type": "mcq",
        "prompt": "Si el usuario olvido la clave del Keyring de GNOME, que accion tecnica se usa para reiniciarlo (con respaldo)?",
        "choices": [
            "mv ~/.local/share/keyrings ~/.local/share/keyrings.bak",
            "rm -rf /etc/passwd",
            "systemctl restart keyringd --factory-reset",
            "chown root:root ~/.bashrc",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_proc_kill_safe_case",
        "type": "mcq",
        "prompt": "En software colgado, que secuencia es mas segura antes de forzar con -9?",
        "choices": [
            "Identificar PID con ps/top y usar kill PID; solo si no responde, kill -9 PID.",
            "Usar kill -9 siempre primero para ahorrar tiempo.",
            "Reiniciar el equipo inmediatamente.",
            "Borrar los logs del sistema.",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_logs_cups_journal",
        "type": "mcq",
        "prompt": "Si impresion falla por servicio cups, selecciona el comando COMPLETO para ver sus ultimos eventos.",
        "choices": ["journalctl -u cups -n 50", "tail -f cups", "lpstat -u cups -n 50", "systemctl log cups"],
        "correct": 0,
    },
    {
        "id": "cmd_chmod_plusx_case",
        "type": "mcq",
        "prompt": "En el caso de que queramos ejecutar un archivo y no se ejecuta, que comando aplica para que tenga permisos de ejecucion y resolverlo?",
        "choices": ["chmod +x archivo", "chown root:root archivo", "rm -rf archivo", "apt reinstall archivo"],
        "correct": 0,
    },
    {
        "id": "cmd_fw_enable",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para habilitar (subir) el firewall UFW.",
        "choices": ["ufw enable", "ufw start", "systemctl start iptables", "firewall --up"],
        "correct": 0,
    },
    {
        "id": "cmd_fw_disable",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para bajar el firewall UFW.",
        "choices": ["ufw disable", "ufw stop", "systemctl stop iptables", "firewall --down"],
        "correct": 0,
    },
    {
        "id": "cmd_chmod_num_read",
        "type": "mcq",
        "prompt": "En chmod 640, el grupo tiene permiso de lectura?",
        "choices": ["Si", "No", "Solo ejecucion", "Solo escritura"],
        "correct": 0,
    },
    {
        "id": "cmd_chmod_num_write",
        "type": "mcq",
        "prompt": "En chmod 754, otros (others) tienen permiso de escritura?",
        "choices": ["Si", "No", "Solo root", "Depende del propietario"],
        "correct": 1,
    },
    {
        "id": "cmd_chmod_num_exec",
        "type": "mcq",
        "prompt": "En chmod 751, el grupo tiene permiso de ejecucion?",
        "choices": ["Si", "No", "Solo lectura", "Solo escritura"],
        "correct": 0,
    },
    {
        "id": "cmd_whoami_user",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para mostrar el usuario actual en la terminal.",
        "choices": ["whoami", "who", "w", "users -a"],
        "correct": 0,
    },
    {
        "id": "cmd_last_recent_login",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver quien fue la ultima persona en conectarse al equipo.",
        "choices": ["last -n 1", "whoami", "w", "users"],
        "correct": 0,
    },
    {
        "id": "cmd_proc_kill",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para terminar el proceso con PID 4321 de forma normal.",
        "choices": ["kill 4321", "kill -9 4321", "pkill 4321", "renice -n 19 4321"],
        "correct": 0,
    },
    {
        "id": "cmd_proc_kill9",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para forzar la terminacion del proceso con PID 4321.",
        "choices": ["kill -9 4321", "kill 4321", "pkill -f 4321", "nice -n -5 4321"],
        "correct": 0,
    },
    {
        "id": "cmd_proc_pkill",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para terminar todos los procesos llamados firefox.",
        "choices": ["pkill firefox", "kill firefox", "kill -9 firefox", "ps aux | pkill"],
        "correct": 0,
    },
    {
        "id": "cmd_proc_nice_renice",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para cambiar la prioridad de un proceso en ejecucion (PID 4321) a niceness 10.",
        "choices": ["renice 10 -p 4321", "nice -n 10 4321", "kill -10 4321", "pkill -n 10 4321"],
        "correct": 0,
    },
    {
        "id": "cmd_net_ip_a",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver direcciones IP e interfaces de red.",
        "choices": ["ip a", "ifconfig -r", "route -n", "ss -a"],
        "correct": 0,
    },
    {
        "id": "cmd_net_ip_route",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver la tabla de rutas del sistema.",
        "choices": ["ip route", "ip a", "netstat -i", "route add"],
        "correct": 0,
    },
    {
        "id": "cmd_net_ping",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para hacer 4 pruebas ICMP al host 10.0.0.10.",
        "choices": ["ping -c 4 10.0.0.10", "ping 10.0.0.10 -n 4", "curl 10.0.0.10", "ip route 10.0.0.10"],
        "correct": 0,
    },
    {
        "id": "cmd_net_ss_tulnp",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar puertos en escucha con PID/proceso.",
        "choices": ["ss -tulnp", "ss -an", "netstat -r", "ip link"],
        "correct": 0,
    },
    {
        "id": "cmd_net_curl_internal",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para consultar un endpoint interno de prueba en http://intranet.local/health.",
        "choices": ["curl http://intranet.local/health", "ping http://intranet.local/health", "ss http://intranet.local/health", "ip a intranet.local"],
        "correct": 0,
    },
    {
        "id": "cmd_cron_edit",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para editar las tareas programadas del usuario actual.",
        "choices": ["crontab -e", "crontab -l", "cron -e", "systemctl edit cron"],
        "correct": 0,
    },
    {
        "id": "cmd_cron_list",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar las tareas cron del usuario actual.",
        "choices": ["crontab -l", "crontab -e", "cron -l", "cat /etc/cron.d"],
        "correct": 0,
    },
    {
        "id": "cmd_copy_rsync_local",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para sincronizar /etc hacia /tmp/backup_etc en el mismo equipo.",
        "choices": [
            "rsync -av /etc/ /tmp/backup_etc/",
            "cp -r /etc /tmp/backup_etc --sync",
            "rsync /etc /tmp/backup_etc -delete",
            "scp -r /etc /tmp/backup_etc",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_copy_rsync_remote",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para sincronizar /var/log al host remoto backup@10.10.10.20:/srv/backup/logs.",
        "choices": [
            "rsync -av /var/log/ backup@10.10.10.20:/srv/backup/logs/",
            "scp /var/log backup@10.10.10.20:/srv/backup/logs/ -a",
            "rsync -av backup@10.10.10.20:/var/log/ /srv/backup/logs/",
            "cp -r /var/log backup@10.10.10.20:/srv/backup/logs/",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_user_useradd",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para crear el usuario operador con home y shell /bin/bash.",
        "choices": [
            "useradd -m -s /bin/bash operador",
            "adduser operador --shell /bin/bash --no-home",
            "usermod -m -s /bin/bash operador",
            "passwd -m -s /bin/bash operador",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_user_usermod_group",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para agregar el usuario operador al grupo sudo sin quitarle otros grupos.",
        "choices": [
            "usermod -aG sudo operador",
            "usermod -G sudo operador",
            "groupadd sudo operador",
            "passwd -G sudo operador",
        ],
        "correct": 0,
    },
    {
        "id": "cmd_user_passwd",
        "type": "shell",
        "title": "Laboratorio: Password de usuario",
        "prompt": "Cambia la contrasena del usuario operador y valida en /etc/shadow que su registro existe con hash.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [
            r"^(sudo\s+)?passwd\s+operador\s*&&\s*(sudo\s+)?grep\s+operador\s+/etc/shadow$",
            r"^(sudo\s+)?passwd\s+operador\s*;\s*(sudo\s+)?grep\s+operador\s+/etc/shadow$",
            r"^(sudo\s+)?passwd\s+operador\s*&&\s*(sudo\s+)?cat\s+/etc/shadow$",
            r"^(sudo\s+)?passwd\s+operador\s*;\s*(sudo\s+)?cat\s+/etc/shadow$",
        ],
        "expected": "passwd operador && grep operador /etc/shadow",
        "success_output": "Password actualizada y registro de operador verificado en /etc/shadow.",
    },
    {
        "id": "cmd_user_id",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para ver UID, GID y grupos efectivos del usuario actual.",
        "choices": ["id", "whoami -g", "groups -a", "users -id"],
        "correct": 0,
    },
    {
        "id": "cmd_user_groups",
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para listar los grupos del usuario actual.",
        "choices": ["groups", "id -u", "who", "users -g"],
        "correct": 0,
    },
]

HISTORY_QUESTIONS = [
    {
        "id": "hist_linus_date",
        "type": "mcq",
        "prompt": "Quien desarrollo la primera version del kernel Linux y en que anio se publico por primera vez?",
        "choices": [
            "Linus Torvalds, 1991",
            "Richard Stallman, 1984",
            "Ken Thompson, 1973",
            "Dennis Ritchie, 1969",
        ],
        "correct": 0,
    },
    {
        "id": "hist_kernel_diff",
        "type": "mcq",
        "prompt": "Cual es la diferencia clave entre kernel monolitico y kernel modular?",
        "choices": [
            "El monolitico integra la mayoria de funciones en un solo espacio; el modular carga componentes por modulos.",
            "El modular no tiene drivers.",
            "El monolitico no soporta procesos.",
            "No hay diferencia tecnica real.",
        ],
        "correct": 0,
    },
    {
        "id": "hist_kernel_monolithic_adv",
        "type": "mcq",
        "prompt": "En general, que ventaja suele tener un kernel monolitico frente a uno con mas modularidad?",
        "choices": [
            "Menor overhead por llamadas internas al tener mas componentes en espacio kernel.",
            "Carga de modulos en caliente mas flexible.",
            "Menor acoplamiento entre subsistemas.",
            "Siempre mejor seguridad por defecto.",
        ],
        "correct": 0,
    },
    {
        "id": "hist_kernel_modular_adv",
        "type": "mcq",
        "prompt": "Que ventaja operativa ofrece un kernel modular?",
        "choices": [
            "Permite cargar o descargar modulos segun hardware/funcion sin recompilar todo el kernel.",
            "Elimina por completo la necesidad de drivers.",
            "Impide fallas de modulos en tiempo de ejecucion.",
            "Siempre consume menos memoria que cualquier monolitico.",
        ],
        "correct": 0,
    },
    {
        "id": "hist_linux_kernel_model",
        "type": "mcq",
        "prompt": "Linux se clasifica comunmente como:",
        "choices": [
            "Kernel monolitico con soporte de modulos cargables (LKM).",
            "Microkernel puro.",
            "Kernel totalmente modular en espacio de usuario.",
            "Kernel hibrido tipo NT sin modulos.",
        ],
        "correct": 0,
    },
    {
        "id": "hist_unix_influence",
        "type": "mcq",
        "prompt": "Linux esta inspirado principalmente en que familia de sistemas operativos?",
        "choices": ["Unix", "MINIX", "DOS", "Windows NT"],
        "correct": 0,
    },
    {
        "id": "hist_gnu_linux",
        "type": "mcq",
        "prompt": "El termino GNU/Linux resalta la combinacion de:",
        "choices": [
            "Kernel Linux + herramientas GNU",
            "Kernel GNU + herramientas Linux",
            "Solo distribuciones comerciales",
            "Linux + BIOS",
        ],
        "correct": 0,
    },
]

SESSION3_IMAGE_QUESTIONS = [
    {
        "id": "s3_rules_pwd",
        "type": "mcq",
        "prompt": "Segun las reglas criticas de organizacion, que comando debes validar SIEMPRE antes de operar en archivos?",
        "choices": ["pwd", "top", "uname -a", "free -m"],
        "correct": 0,
    },
    {
        "id": "s3_rules_rm_i",
        "type": "mcq",
        "prompt": "En las reglas criticas, que variante de rm se recomienda para evitar borrados accidentales?",
        "choices": ["rm -f", "rm -i", "rm -rf /", "rmdir -p"],
        "correct": 1,
    },
]

IMAGE_QUESTIONS = [
    {
        "id": "img_top_issue_swap",
        "type": "image_click",
        "prompt": "Observa la captura de top y haz click en la zona que indica presion de swap.",
        "image_url": "/CursoLinux/static/images/top_snapshot.png",
        "hotspots": [
            {"id": "cpu", "x": 3, "y": 17, "w": 92, "h": 9},
            {"id": "mem", "x": 3, "y": 24, "w": 92, "h": 8},
            {"id": "swap", "x": 3, "y": 42, "w": 92, "h": 9},
            {"id": "zombie", "x": 3, "y": 30, "w": 92, "h": 9},
            {"id": "proc", "x": 3, "y": 58, "w": 92, "h": 14},
        ],
        "correct": "swap",
        "expected": "swap (uso alto de swap)",
    },
    {
        "id": "img_top_issue_cpu",
        "type": "image_click",
        "prompt": "En la captura de top, haz click en el indicador de CPU alta.",
        "image_url": "/CursoLinux/static/images/top_snapshot.png",
        "hotspots": [
            {"id": "cpu", "x": 3, "y": 17, "w": 92, "h": 9},
            {"id": "mem", "x": 3, "y": 24, "w": 92, "h": 8},
            {"id": "swap", "x": 3, "y": 42, "w": 92, "h": 9},
            {"id": "zombie", "x": 3, "y": 30, "w": 92, "h": 9},
            {"id": "proc", "x": 3, "y": 58, "w": 92, "h": 14},
        ],
        "correct": "cpu",
        "expected": "CPU saturada",
    },
    {
        "id": "img_top_issue_mem",
        "type": "image_click",
        "prompt": "En la captura de top, haz click en la linea de memoria (Mem).",
        "image_url": "/CursoLinux/static/images/top_snapshot.png",
        "hotspots": [
            {"id": "cpu", "x": 3, "y": 17, "w": 92, "h": 9},
            {"id": "mem", "x": 3, "y": 24, "w": 92, "h": 8},
            {"id": "swap", "x": 3, "y": 42, "w": 92, "h": 9},
            {"id": "zombie", "x": 3, "y": 30, "w": 92, "h": 9},
            {"id": "proc", "x": 3, "y": 58, "w": 92, "h": 14},
        ],
        "correct": "mem",
        "expected": "Memoria (Mem)",
    },
    {
        "id": "img_top_issue_zombie",
        "type": "image_click",
        "prompt": "Observa top y haz click en la zona donde se reportan procesos zombie.",
        "image_url": "/CursoLinux/static/images/top_snapshot.png",
        "hotspots": [
            {"id": "cpu", "x": 3, "y": 17, "w": 92, "h": 9},
            {"id": "mem", "x": 3, "y": 24, "w": 92, "h": 8},
            {"id": "swap", "x": 3, "y": 42, "w": 92, "h": 9},
            {"id": "zombie", "x": 3, "y": 30, "w": 92, "h": 9},
            {"id": "proc", "x": 3, "y": 58, "w": 92, "h": 14},
        ],
        "correct": "zombie",
        "expected": "contador de procesos zombie",
    },
    {
        "id": "img_top_issue_proc_consumer",
        "type": "image_click",
        "prompt": "En top, haz click en el proceso que aparece como principal consumidor.",
        "image_url": "/CursoLinux/static/images/top_snapshot.png",
        "hotspots": [
            {"id": "cpu", "x": 3, "y": 17, "w": 92, "h": 9},
            {"id": "mem", "x": 3, "y": 24, "w": 92, "h": 8},
            {"id": "swap", "x": 3, "y": 42, "w": 92, "h": 9},
            {"id": "zombie", "x": 3, "y": 30, "w": 92, "h": 9},
            {"id": "proc", "x": 3, "y": 58, "w": 92, "h": 14},
        ],
        "correct": "proc",
        "expected": "proceso consumidor principal",
    },
    {
        "id": "img_htop_issue_process_cpu",
        "type": "image_click",
        "prompt": "En la captura de htop, haz click en la zona que muestra un proceso consumidor de CPU.",
        "image_url": "/CursoLinux/static/images/htop_snapshot.png",
        "hotspots": [
            {"id": "bars", "x": 3, "y": 6, "w": 94, "h": 18},
            {"id": "process", "x": 3, "y": 31, "w": 94, "h": 16},
            {"id": "footer", "x": 3, "y": 86, "w": 94, "h": 10},
        ],
        "correct": "process",
        "expected": "proceso con CPU% alto",
    },
    {
        "id": "img_htop_issue_bars_memswap",
        "type": "image_click",
        "prompt": "En htop, haz click en la zona de barras donde se ve presion de memoria/swap.",
        "image_url": "/CursoLinux/static/images/htop_snapshot.png",
        "hotspots": [
            {"id": "bars", "x": 3, "y": 6, "w": 94, "h": 18},
            {"id": "process", "x": 3, "y": 31, "w": 94, "h": 16},
            {"id": "footer", "x": 3, "y": 86, "w": 94, "h": 10},
        ],
        "correct": "bars",
        "expected": "barras de Mem/Swp",
    },
]

SHELL_EXERCISES = [
    {
        "id": "shell_hidden",
        "type": "shell",
        "title": "Archivos ocultos",
        "prompt": "En /home/alumno/lab existen archivos ocultos. Escribe un comando para listarlos.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^ls\s+-a$", r"^ls\s+-la$", r"^ls\s+-al$"],
        "expected": "ls -a",
        "success_output": ".  ..  .env  .config  notas.txt",
    },
    {
        "id": "shell_delete_tmp",
        "type": "shell",
        "title": "Borrado seguro",
        "prompt": "Debes borrar archivo_tmp.log con confirmacion interactiva.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^rm\s+-i\s+archivo_tmp\.log$"],
        "expected": "rm -i archivo_tmp.log",
        "success_output": "rm: remove regular file 'archivo_tmp.log'? y",
    },
    {
        "id": "shell_tail",
        "type": "shell",
        "title": "Analisis de logs",
        "prompt": "Muestra las ultimas 15 lineas del archivo /var/log/auth.log.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^tail\s+-n\s+15\s+/var/log/auth\.log$", r"^tail\s+-15\s+/var/log/auth\.log$"],
        "expected": "tail -n 15 /var/log/auth.log",
        "success_output": "... (ultimas 15 lineas mostradas) ...",
    },
    {
        "id": "shell_head",
        "type": "shell",
        "title": "Revision rapida",
        "prompt": "Muestra las primeras 10 lineas de /etc/passwd.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^head\s+-n\s+10\s+/etc/passwd$", r"^head\s+-10\s+/etc/passwd$"],
        "expected": "head -n 10 /etc/passwd",
        "success_output": "root:x:0:0:root:/root:/bin/bash\n...",
    },
    {
        "id": "shell_find_zombie",
        "type": "shell",
        "title": "Procesos zombie",
        "prompt": "Escribe un comando para listar procesos zombie usando ps.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^ps\s+aux\s*\|\s*grep\s+Z$", r"^ps\s+-el\s*\|\s*grep\s+Z$"],
        "expected": "ps aux | grep Z",
        "success_output": "root  1234  0.0  0.0  0  0 ?  Z  09:20 0:00 proceso_defunct",
    },
    {
        "id": "shell_systemctl_status",
        "type": "shell",
        "title": "Servicios",
        "prompt": "Muestra el estado del servicio apache2.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^systemctl\s+status\s+apache2$"],
        "expected": "systemctl status apache2",
        "success_output": "apache2.service - The Apache HTTP Server (active/running)",
    },
    {
        "id": "shell_journalctl_errors",
        "type": "shell",
        "title": "Logs de servicio",
        "prompt": "Muestra las ultimas 30 lineas del log del servicio apache2.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^journalctl\s+-u\s+apache2\s+-n\s+30$"],
        "expected": "journalctl -u apache2 -n 30",
        "success_output": "... ultimos eventos de apache2 ...",
    },
    {
        "id": "shell_find_log_recent",
        "type": "shell",
        "title": "Busqueda de archivos",
        "prompt": "Encuentra archivos .log modificados en los ultimos 2 dias dentro de /var/log.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^find\s+/var/log\s+-type\s+f\s+-name\s+[\"']?\*\.log[\"']?\s+-mtime\s+-2$"],
        "expected": "find /var/log -type f -name '*.log' -mtime -2",
        "success_output": "/var/log/syslog\n/var/log/auth.log",
    },
    {
        "id": "shell_find_respaldo_dir",
        "type": "shell",
        "title": "Busqueda con find",
        "prompt": "Busca el directorio respaldo dentro de /home/alumno usando find.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [
            r"^find\s+/home/alumno\s+-type\s+d\s+-name\s+\"?respaldo\"?$",
            r"^find\s+/home/alumno\s+-name\s+\"?respaldo\"?\s+-type\s+d$",
            r"^find\s+/\s+-name\s+\"?respaldo\"?$",
            r"^find\s+/\s+-type\s+d\s+-name\s+\"?respaldo\"?$",
            r"^find\s+/\s+-name\s+\"?respaldo\"?\s+-type\s+d$",
        ],
        "expected": "find /home/alumno -type d -name respaldo",
        "success_output": "/home/alumno/respaldo",
    },
    {
        "id": "shell_du_heavy",
        "type": "shell",
        "title": "Espacio en disco",
        "prompt": "Muestra las 5 rutas con mayor consumo de espacio en /var.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^du\s+-h\s+/var\s*\|\s*sort\s+-hr\s*\|\s*head\s+-n\s+5$"],
        "expected": "du -h /var | sort -hr | head -n 5",
        "success_output": "12G /var/lib\n2.1G /var/log ...",
    },
    {
        "id": "shell_fix_script_perm",
        "type": "shell",
        "title": "Permisos",
        "prompt": "Asigna propietario alumno:soporte a script.sh y permisos 700 en un solo comando.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^chown\s+alumno:soporte\s+script\.sh\s*&&\s*chmod\s+700\s+script\.sh$"],
        "expected": "chown alumno:soporte script.sh && chmod 700 script.sh",
        "success_output": "Propietario y permisos actualizados.",
    },
    {
        "id": "shell_chmod_user_exec",
        "type": "shell",
        "title": "Permiso de ejecucion",
        "prompt": "Otorga permiso de ejecucion SOLO al usuario propietario sobre script.sh.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^chmod\s+u\+x\s+script\.sh$"],
        "expected": "chmod u+x script.sh",
        "success_output": "Permiso de ejecucion agregado para el usuario propietario.",
    },
    {
        "id": "shell_mkdir_copy_subdir",
        "type": "shell",
        "title": "Subdirectorio y copia",
        "prompt": "Crea un subdirectorio llamado respaldo y copia notas.txt dentro de ese subdirectorio.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [
            r"^mkdir\s+respaldo\s*&&\s*cp\s+notas\.txt\s+respaldo/?$",
            r"^mkdir\s+respaldo\s*;\s*cp\s+notas\.txt\s+respaldo/?$",
        ],
        "expected": "mkdir respaldo && cp notas.txt respaldo/",
        "success_output": "Subdirectorio creado y archivo copiado en respaldo.",
    },
    {
        "id": "shell_shadow_hashes",
        "type": "shell",
        "title": "Laboratorio: Analisis de /etc/shadow",
        "prompt": "Realiza el laboratorio: 1) muestra /etc/shadow y 2) filtra la cuenta operador para ubicar su hash.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [
            r"^(sudo\s+)?cat\s+/etc/shadow\s*&&\s*(sudo\s+)?grep\s+operador\s+/etc/shadow$",
            r"^(sudo\s+)?cat\s+/etc/shadow\s*;\s*(sudo\s+)?grep\s+operador\s+/etc/shadow$",
            r"^(sudo\s+)?more\s+/etc/shadow\s*&&\s*(sudo\s+)?grep\s+operador\s+/etc/shadow$",
            r"^(sudo\s+)?more\s+/etc/shadow\s*;\s*(sudo\s+)?grep\s+operador\s+/etc/shadow$",
            r"^(sudo\s+)?cat\s+shadow\s*&&\s*(sudo\s+)?grep\s+operador\s+shadow$",
            r"^(sudo\s+)?cat\s+shadow\s*;\s*(sudo\s+)?grep\s+operador\s+shadow$",
            r"^(sudo\s+)?more\s+shadow\s*&&\s*(sudo\s+)?grep\s+operador\s+shadow$",
            r"^(sudo\s+)?more\s+shadow\s*;\s*(sudo\s+)?grep\s+operador\s+shadow$",
        ],
        "expected": "cat /etc/shadow && grep operador /etc/shadow",
        "success_output": "Laboratorio completado: /etc/shadow revisado y cuenta operador localizada.",
    },
    {
        "id": "shell_systemctl_start_service",
        "type": "shell",
        "title": "Arranque de servicio",
        "prompt": "Arranca el servicio apache2 usando systemctl.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?systemctl\s+start\s+apache2$"],
        "expected": "systemctl start apache2",
        "success_output": "Servicio apache2 iniciado correctamente.",
    },
    {
        "id": "shell_init_shutdown",
        "type": "shell",
        "title": "Apagado con init",
        "prompt": "Apaga el equipo usando init sin usar reboot.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?init\s+0$"],
        "expected": "init 0",
        "success_output": "Comando de apagado enviado (simulado).",
    },
    {
        "id": "shell_ss_listen",
        "type": "shell",
        "title": "Puertos",
        "prompt": "Lista puertos TCP/UDP en escucha mostrando PID y proceso.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^ss\s+-tulnp$"],
        "expected": "ss -tulnp",
        "success_output": "tcp LISTEN 0 128 *:22 ... users:(('sshd',pid=930,...))",
    },
    {
        "id": "shell_grep_tail",
        "type": "shell",
        "title": "Filtrado de errores",
        "prompt": "Filtra la palabra error en /var/log/syslog y muestra las ultimas 20 coincidencias.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [
            r"^grep\s+-i\s+error\s+/var/log/syslog\s*\|\s*tail\s+-n\s+20$",
            r"^cat\s+/var/log/syslog\s*\|\s*grep\s+-i\s+error\s*\|\s*tail\s+-n\s+20$",
            r"^cat\s+/var/log/syslog\s*\|\s*grep\s+error\s*\|\s*tail\s+-n\s+20$",
            r"^cat\s+/var/log/syslog\s*\|\s*grep\s+-i\s+error$",
            r"^cat\s+/var/log/syslog\s*\|\s*grep\s+error$",
        ],
        "expected": "grep -i error /var/log/syslog | tail -n 20",
        "success_output": "... lineas de error recientes ...",
    },
    {
        "id": "shell_tar_create",
        "type": "shell",
        "title": "Respaldo",
        "prompt": "Crea un comprimido respaldo.tar.gz del directorio /etc.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^tar\s+-czf\s+respaldo\.tar\.gz\s+/etc$"],
        "expected": "tar -czf respaldo.tar.gz /etc",
        "success_output": "respaldo.tar.gz creado correctamente.",
    },
    {
        "id": "shell_tar_extract",
        "type": "shell",
        "title": "Restauracion",
        "prompt": "Extrae respaldo.tar.gz en el directorio actual.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^tar\s+-xzf\s+respaldo\.tar\.gz$"],
        "expected": "tar -xzf respaldo.tar.gz",
        "success_output": "Archivos extraidos desde respaldo.tar.gz",
    },
    {
        "id": "shell_cups_printers",
        "type": "shell",
        "title": "CUPS - impresoras",
        "prompt": "Muestra las impresoras configuradas en CUPS.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^lpstat\s+-p$"],
        "expected": "lpstat -p",
        "success_output": "printer HP_Oficina is idle. enabled since ...",
    },
    {
        "id": "shell_cups_jobs",
        "type": "shell",
        "title": "CUPS - cola",
        "prompt": "Muestra la cola de trabajos de impresion de CUPS.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^lpstat\s+-o$"],
        "expected": "lpstat -o",
        "success_output": "HP_Oficina-245  usuario  1024 bytes ...",
    },
    {
        "id": "shell_cups_service",
        "type": "shell",
        "title": "CUPS - servicio",
        "prompt": "Muestra el estado del servicio cups.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^systemctl\s+status\s+cups$"],
        "expected": "systemctl status cups",
        "success_output": "cups.service - CUPS Scheduler (active/running)",
    },
    {
        "id": "shell_cat_1",
        "type": "shell",
        "title": "CAT - notas",
        "prompt": "Muestra el contenido del archivo notas.txt en el directorio actual.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^cat\s+notas\.txt$", r"^cat\s+\./notas\.txt$"],
        "expected": "cat notas.txt",
        "success_output": "Contenido de notas.txt mostrado.",
    },
    {
        "id": "shell_cat_2",
        "type": "shell",
        "title": "CAT - passwd",
        "prompt": "Muestra el contenido del archivo /etc/passwd.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^cat\s+/etc/passwd$"],
        "expected": "cat /etc/passwd",
        "success_output": "Contenido de /etc/passwd mostrado.",
    },
    {
        "id": "shell_cat_3",
        "type": "shell",
        "title": "CAT - auth.log",
        "prompt": "Muestra el contenido del archivo /var/log/auth.log.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^cat\s+/var/log/auth\.log$"],
        "expected": "cat /var/log/auth.log",
        "success_output": "Contenido de /var/log/auth.log mostrado.",
    },
    {
        "id": "shell_cat_4",
        "type": "shell",
        "title": "CAT - script",
        "prompt": "Muestra el contenido del archivo script.sh del laboratorio.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^cat\s+script\.sh$", r"^cat\s+\./script\.sh$"],
        "expected": "cat script.sh",
        "success_output": "Contenido de script.sh mostrado.",
    },
    {
        "id": "shell_df_1",
        "type": "shell",
        "title": "DF - general",
        "prompt": "Muestra el uso de disco en formato legible.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^df\s+-h$"],
        "expected": "df -h",
        "success_output": "Uso de disco mostrado.",
    },
    {
        "id": "shell_df_2",
        "type": "shell",
        "title": "DF - raiz",
        "prompt": "Consulta el uso de disco solo para la ruta /.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^df\s+-h\s+/$", r"^df\s+/\s+-h$"],
        "expected": "df -h /",
        "success_output": "Uso de disco de / mostrado.",
    },
    {
        "id": "shell_df_3",
        "type": "shell",
        "title": "DF - /var",
        "prompt": "Consulta el uso de disco para la ruta /var.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^df\s+-h\s+/var$", r"^df\s+/var\s+-h$"],
        "expected": "df -h /var",
        "success_output": "Uso de disco de /var mostrado.",
    },
    {
        "id": "shell_df_4",
        "type": "shell",
        "title": "DF - inodos",
        "prompt": "Muestra el uso de inodos del sistema.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^df\s+-i$"],
        "expected": "df -i",
        "success_output": "Uso de inodos mostrado.",
    },
    {
        "id": "shell_mv_1",
        "type": "shell",
        "title": "MV - renombrar",
        "prompt": "Renombra archivo_tmp.log a archivo_tmp.bak en el directorio actual.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^mv\s+archivo_tmp\.log\s+archivo_tmp\.bak$"],
        "expected": "mv archivo_tmp.log archivo_tmp.bak",
        "success_output": "Archivo renombrado correctamente.",
    },
    {
        "id": "shell_mv_2",
        "type": "shell",
        "title": "MV - mover a /var/log",
        "prompt": "Mueve notas.txt al directorio /var/log.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^mv\s+notas\.txt\s+/var/log/?$", r"^mv\s+notas\.txt\s+/var/log/notas\.txt$"],
        "expected": "mv notas.txt /var/log/",
        "success_output": "Archivo movido a /var/log.",
    },
    {
        "id": "shell_mv_3",
        "type": "shell",
        "title": "MV - mover script",
        "prompt": "Mueve script.sh al directorio /tmp.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^mv\s+script\.sh\s+/tmp/?$", r"^mv\s+script\.sh\s+/tmp/script\.sh$"],
        "expected": "mv script.sh /tmp/",
        "success_output": "Archivo movido a /tmp.",
    },
    {
        "id": "shell_mv_4",
        "type": "shell",
        "title": "MV - mover respaldo",
        "prompt": "Mueve respaldo.tar.gz al directorio /var/log.",
        "terminal_hint": "alumno@linux:~/lab$",
        "accepted": [r"^mv\s+respaldo\.tar\.gz\s+/var/log/?$", r"^mv\s+respaldo\.tar\.gz\s+/var/log/respaldo\.tar\.gz$"],
        "expected": "mv respaldo.tar.gz /var/log/",
        "success_output": "Archivo movido a /var/log.",
    },
    {
        "id": "shell_disk_full_case1",
        "type": "shell",
        "title": "Disco lleno - diagnostico 1",
        "prompt": "Caso practico: el sistema reporta disco lleno. Verifica el uso de disco de /var en formato legible.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?df\s+-h\s+/var$", r"^(sudo\s+)?df\s+/var\s+-h$"],
        "expected": "df -h /var",
        "success_output": "Uso de disco de /var mostrado para diagnostico.",
    },
    {
        "id": "shell_disk_full_case2",
        "type": "shell",
        "title": "Disco lleno - diagnostico 2",
        "prompt": "Caso practico: identifica las 5 rutas que mas espacio consumen dentro de /var.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?du\s+-h\s+/var\s*\|\s*sort\s+-hr\s*\|\s*head\s+-n\s+5$"],
        "expected": "du -h /var | sort -hr | head -n 5",
        "success_output": "Top de consumo en /var mostrado.",
    },
    {
        "id": "shell_disk_du_varlog",
        "type": "shell",
        "title": "Disco lleno - logs pesados",
        "prompt": "Localiza carpetas pesadas dentro de /var/log.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?du\s+-sh\s+/var/log/\*$"],
        "expected": "du -sh /var/log/*",
        "success_output": "Consumo por carpeta en /var/log mostrado.",
    },
    {
        "id": "shell_disk_clean_apt",
        "type": "shell",
        "title": "Disco lleno - limpieza apt",
        "prompt": "Caso practico: limpia cache de paquetes para liberar espacio.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?apt\s+clean$"],
        "expected": "apt clean",
        "success_output": "Cache de apt limpiada correctamente.",
    },
    {
        "id": "shell_disk_autoremove_purge",
        "type": "shell",
        "title": "Disco lleno - purge de obsoletos",
        "prompt": "Caso practico: elimina paquetes/dependencias obsoletas con purge.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?apt\s+autoremove\s+--purge(\s+-y)?$"],
        "expected": "apt autoremove --purge -y",
        "success_output": "Paquetes obsoletos eliminados con purge.",
    },
    {
        "id": "shell_keyring_reset",
        "type": "shell",
        "title": "Keyring GNOME",
        "prompt": "El usuario olvido su clave del keyring. Renombra el directorio de keyrings para reinicio controlado.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^mv\s+~/.local/share/keyrings\s+~/.local/share/keyrings\.bak$"],
        "expected": "mv ~/.local/share/keyrings ~/.local/share/keyrings.bak",
        "success_output": "Keyring renombrado para reinicializacion en siguiente login.",
    },
    {
        "id": "shell_samba_smbpasswd",
        "type": "shell",
        "title": "Samba - credencial usuario",
        "prompt": "Configura/actualiza la clave Samba del usuario alumno.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?smbpasswd\s+-a\s+alumno$"],
        "expected": "smbpasswd -a alumno",
        "success_output": "Usuario Samba alumno actualizado correctamente.",
    },
    {
        "id": "shell_samba_testparm",
        "type": "shell",
        "title": "Samba - validar configuracion",
        "prompt": "Valida la sintaxis de la configuracion Samba.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^(sudo\s+)?testparm$"],
        "expected": "testparm",
        "success_output": "Configuracion Samba validada (sin errores de sintaxis).",
    },
    {
        "id": "shell_kill_hung_app",
        "type": "shell",
        "title": "Software colgado",
        "prompt": "Finaliza de forma normal el proceso colgado con PID 4321.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^kill\s+4321$"],
        "expected": "kill 4321",
        "success_output": "Senal TERM enviada al proceso 4321.",
    },
    {
        "id": "shell_journalctl_cups",
        "type": "shell",
        "title": "Logs de impresion",
        "prompt": "Consulta las ultimas 50 lineas del servicio de impresion cups.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^journalctl\s+-u\s+cups\s+-n\s+50$"],
        "expected": "journalctl -u cups -n 50",
        "success_output": "Eventos recientes de cups mostrados.",
    },
    {
        "id": "shell_journalctl_errors_priority",
        "type": "shell",
        "title": "Logs - errores recientes",
        "prompt": "Muestra solo errores recientes del sistema (prioridad err) en las ultimas 50 lineas.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [r"^journalctl\s+-p\s+err\s+-n\s+50$"],
        "expected": "journalctl -p err -n 50",
        "success_output": "Errores recientes del sistema mostrados.",
    },
]


def utcnow_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def elapsed_seconds(started_at: str, ended_at: Optional[str] = None) -> int:
    s = parse_iso(started_at)
    if not s:
        return 0
    e = parse_iso(ended_at) if ended_at else datetime.utcnow()
    if not e:
        e = datetime.utcnow()
    return max(0, int((e - s).total_seconds()))


def normalize_key(value: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "", ascii_value.lower())


def parse_students_csv(csv_text: str) -> List[str]:
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    if not rows:
        return []

    header = rows[0]
    data_rows = rows[1:] if len(rows) > 1 else []

    candidate_idx = None
    for idx, col in enumerate(header):
        key = normalize_key(col)
        if any(tag in key for tag in ["nombre", "alumno", "student", "name"]):
            candidate_idx = idx
            break

    if candidate_idx is None:
        best_count = -1
        for idx in range(min(len(header), 8)):
            count = sum(1 for row in data_rows if idx < len(row) and row[idx].strip())
            if count > best_count:
                best_count = count
                candidate_idx = idx

    if candidate_idx is None:
        return []

    students = []
    seen = set()
    for row in data_rows:
        if candidate_idx >= len(row):
            continue
        name = row[candidate_idx].strip()
        if not name:
            continue
        if normalize_key(name) in {"nombre", "alumno", "name", "student"}:
            continue
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        students.append(name)
    return students


def fetch_students_from_sheet(csv_url: str) -> List[str]:
    response = requests.get(csv_url, timeout=20)
    response.raise_for_status()
    text = response.content.decode("utf-8-sig", errors="replace")
    students = parse_students_csv(text)
    if not students:
        raise ValueError("No se encontraron alumnos en la hoja")
    return students


def get_students() -> List[str]:
    now = time.time()
    cache_age = now - _STUDENTS_CACHE["loaded_at"]
    if _STUDENTS_CACHE["students"] and cache_age < STUDENTS_CACHE_TTL_SECONDS:
        return _STUDENTS_CACHE["students"]

    try:
        students = fetch_students_from_sheet(GOOGLE_SHEET_CSV_URL)
        _STUDENTS_CACHE["students"] = students
        _STUDENTS_CACHE["loaded_at"] = now
    except Exception:
        if not _STUDENTS_CACHE["students"]:
            _STUDENTS_CACHE["students"] = DEFAULT_STUDENTS.copy()
            _STUDENTS_CACHE["loaded_at"] = now

    return _STUDENTS_CACHE["students"]


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def parse_bool_setting(value: Optional[str], default: bool) -> bool:
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "si", "on"}


def get_bool_setting(conn: sqlite3.Connection, key: str, default: bool) -> bool:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    if not row:
        return bool(default)
    return parse_bool_setting(row["value"], default)


def set_bool_setting(conn: sqlite3.Connection, key: str, value: bool) -> None:
    conn.execute(
        """
        INSERT INTO app_settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, "1" if value else "0"),
    )


def get_student_level(conn: sqlite3.Connection, student_email: str, default_level: int = 1) -> int:
    email = normalize_email(student_email)
    if not email:
        return int(default_level)
    row = conn.execute(
        "SELECT exam_level FROM student_levels WHERE student_email = ?",
        (email,),
    ).fetchone()
    if not row:
        return int(default_level)
    try:
        lvl = int(row["exam_level"])
    except Exception:
        lvl = int(default_level)
    return 2 if lvl >= 2 else 1


def set_student_level(conn: sqlite3.Connection, student_email: str, exam_level: int) -> int:
    email = normalize_email(student_email)
    lvl = 2 if int(exam_level) >= 2 else 1
    if not email:
        return lvl
    conn.execute(
        """
        INSERT INTO student_levels (student_email, exam_level, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(student_email) DO UPDATE
        SET exam_level = excluded.exam_level,
            updated_at = excluded.updated_at
        """,
        (email, lvl, utcnow_iso()),
    )
    return lvl


def init_db() -> None:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS exam_sessions (
                session_token TEXT PRIMARY KEY,
                student_name TEXT NOT NULL,
                student_email TEXT NOT NULL DEFAULT '',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                current_index INTEGER NOT NULL DEFAULT 0,
                max_reached_index INTEGER NOT NULL DEFAULT 0,
                total_items INTEGER NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL DEFAULT 0,
                resets_count INTEGER NOT NULL DEFAULT 0,
                exam_level INTEGER NOT NULL DEFAULT 1,
                exam_payload TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT NOT NULL,
                item_index INTEGER NOT NULL,
                item_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                prompt TEXT NOT NULL,
                user_answer TEXT NOT NULL,
                distro_guess TEXT NOT NULL DEFAULT '',
                command_trace TEXT NOT NULL DEFAULT '',
                extra_text TEXT NOT NULL DEFAULT '',
                is_correct INTEGER NOT NULL,
                expected TEXT,
                submitted_at TEXT NOT NULL,
                FOREIGN KEY(session_token) REFERENCES exam_sessions(session_token),
                UNIQUE(session_token, item_index)
            );

            CREATE TABLE IF NOT EXISTS question_timing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT NOT NULL,
                item_index INTEGER NOT NULL,
                seconds_spent REAL NOT NULL DEFAULT 0,
                last_entered_at TEXT,
                FOREIGN KEY(session_token) REFERENCES exam_sessions(session_token),
                UNIQUE(session_token, item_index)
            );

            CREATE TABLE IF NOT EXISTS exam_archives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT NOT NULL,
                saved_at TEXT NOT NULL,
                saved_by TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS response_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT NOT NULL,
                item_index INTEGER NOT NULL,
                item_id TEXT NOT NULL,
                attempt_no INTEGER NOT NULL,
                user_answer TEXT NOT NULL,
                is_correct INTEGER NOT NULL,
                submitted_at TEXT NOT NULL,
                FOREIGN KEY(session_token) REFERENCES exam_sessions(session_token)
            );

            CREATE TABLE IF NOT EXISTS student_item_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_key TEXT NOT NULL,
                item_id TEXT NOT NULL,
                seen_at TEXT NOT NULL,
                UNIQUE(student_key, item_id)
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS student_levels (
                student_email TEXT PRIMARY KEY,
                exam_level INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            );
            """
        )
        cols = conn.execute("PRAGMA table_info(exam_sessions)").fetchall()
        names = {c["name"] for c in cols}
        if "resets_count" not in names:
            conn.execute("ALTER TABLE exam_sessions ADD COLUMN resets_count INTEGER NOT NULL DEFAULT 0")
        if "max_reached_index" not in names:
            conn.execute("ALTER TABLE exam_sessions ADD COLUMN max_reached_index INTEGER NOT NULL DEFAULT 0")
        if "student_email" not in names:
            conn.execute("ALTER TABLE exam_sessions ADD COLUMN student_email TEXT NOT NULL DEFAULT ''")
        if "summary_viewed_at" not in names:
            conn.execute("ALTER TABLE exam_sessions ADD COLUMN summary_viewed_at TEXT")
        if "exam_level" not in names:
            conn.execute("ALTER TABLE exam_sessions ADD COLUMN exam_level INTEGER NOT NULL DEFAULT 1")
        response_cols = conn.execute("PRAGMA table_info(responses)").fetchall()
        response_names = {c["name"] for c in response_cols}
        if "distro_guess" not in response_names:
            conn.execute("ALTER TABLE responses ADD COLUMN distro_guess TEXT NOT NULL DEFAULT ''")
        if "command_trace" not in response_names:
            conn.execute("ALTER TABLE responses ADD COLUMN command_trace TEXT NOT NULL DEFAULT ''")
        if "extra_text" not in response_names:
            conn.execute("ALTER TABLE responses ADD COLUMN extra_text TEXT NOT NULL DEFAULT ''")


def _prefer_unseen(pool: List[Dict], seen_ids: set, k: int) -> List[Dict]:
    if k <= 0 or not pool:
        return []
    unseen = [q for q in pool if q.get("id") not in seen_ids]
    if len(unseen) >= k:
        return random.sample(unseen, k=k)
    # Si ya se agotaron en el ciclo, se reutiliza el pool completo.
    if len(pool) <= k:
        return random.sample(pool, k=len(pool))
    chosen = unseen[:]
    remaining = k - len(chosen)
    used_ids = {q.get("id") for q in chosen}
    fallback = [q for q in pool if q.get("id") not in used_ids]
    chosen.extend(random.sample(fallback, k=min(remaining, len(fallback))))
    return chosen


def build_exam(student_key: Optional[str] = None, conn: Optional[sqlite3.Connection] = None, exam_level: int = 1) -> List[Dict]:
    seen_ids = set()
    if student_key and conn is not None:
        rows = conn.execute(
            "SELECT item_id FROM student_item_history WHERE student_key = ?",
            (student_key,),
        ).fetchall()
        seen_ids = {r["item_id"] for r in rows}

    level = 2 if int(exam_level) >= 2 else 1
    if level >= 2:
        level2_cmd_prefixes = (
            "cmd_disk_",
            "cmd_keyring_",
            "cmd_priv_",
            "cmd_samba_",
            "cmd_logs_",
            "cmd_proc_",
            "cmd_pkg_",
            "cmd_apt_",
            "cmd_dpkg_",
        )
        level2_cmd_ids = {
            "cmd_du_sort",
            "cmd_chmod_plusx_case",
            "cmd_chmod_chown",
            "cmd_systemctl_restart",
            "cmd_journalctl_last",
            "cmd_cups_status",
            "cmd_cups_restart",
            "cmd_cups_printers",
            "cmd_cups_jobs",
        }
        level2_shell_prefixes = (
            "shell_disk_",
            "shell_keyring_",
            "shell_samba_",
            "shell_kill_",
            "shell_journalctl_",
        )
        level2_shell_ids = {
            "shell_systemctl_status",
            "shell_systemctl_start_service",
            "shell_grep_tail",
            "shell_chmod_user_exec",
            "shell_fix_script_perm",
        }
        level2_command_pool = [
            q
            for q in COMMAND_QUESTIONS
            if q["id"].startswith(level2_cmd_prefixes) or q["id"] in level2_cmd_ids
        ]
        level2_shell_pool = [
            q
            for q in SHELL_EXERCISES
            if q["id"].startswith(level2_shell_prefixes) or q["id"] in level2_shell_ids
        ]
        command = _prefer_unseen(level2_command_pool, seen_ids, min(12, len(level2_command_pool)))
        history = _prefer_unseen(HISTORY_QUESTIONS, seen_ids, min(1, len(HISTORY_QUESTIONS)))
        session3 = _prefer_unseen(SESSION3_IMAGE_QUESTIONS, seen_ids, min(2, len(SESSION3_IMAGE_QUESTIONS)))
        images = _prefer_unseen(IMAGE_QUESTIONS, seen_ids, min(2, len(IMAGE_QUESTIONS)))
        shell = _prefer_unseen(level2_shell_pool, seen_ids, min(10, len(level2_shell_pool)))
        items = command + history + session3 + images + shell
        target_total = 25
        if len(items) < target_total:
            used = {str(x.get("id") or "") for x in items}
            filler_pool = [q for q in (COMMAND_QUESTIONS + SHELL_EXERCISES) if str(q.get("id") or "") not in used]
            need = max(0, target_total - len(items))
            if filler_pool and need > 0:
                items.extend(_prefer_unseen(filler_pool, seen_ids, min(need, len(filler_pool))))
    else:
        cups_cmd = [q for q in COMMAND_QUESTIONS if q["id"].startswith("cmd_cups_")]
        fw_cmd = [q for q in COMMAND_QUESTIONS if q["id"].startswith("cmd_fw_")]
        chmod_num_cmd = [q for q in COMMAND_QUESTIONS if q["id"].startswith("cmd_chmod_num_")]
        pkg_cmd = [q for q in COMMAND_QUESTIONS if q["id"].startswith("cmd_pkg_")]
        other_cmd = [
            q
            for q in COMMAND_QUESTIONS
            if not q["id"].startswith("cmd_cups_")
            and not q["id"].startswith("cmd_fw_")
            and not q["id"].startswith("cmd_chmod_num_")
            and not q["id"].startswith("cmd_pkg_")
        ]
        kernel_hist = [q for q in HISTORY_QUESTIONS if q["id"].startswith("hist_kernel_")]
        other_hist = [q for q in HISTORY_QUESTIONS if not q["id"].startswith("hist_kernel_")]

        command: List[Dict] = []
        if cups_cmd:
            command.extend(_prefer_unseen(cups_cmd, seen_ids, 1))
        if fw_cmd:
            command.extend(_prefer_unseen(fw_cmd, seen_ids, 1))
        if chmod_num_cmd:
            command.extend(_prefer_unseen(chmod_num_cmd, seen_ids, 1))
        if pkg_cmd:
            command.extend(_prefer_unseen(pkg_cmd, seen_ids, 1))
        remaining_cmd = max(0, min(12, len(COMMAND_QUESTIONS)) - len(command))
        pool_cmd = [q for q in other_cmd if q not in command]
        if pool_cmd and remaining_cmd > 0:
            command.extend(_prefer_unseen(pool_cmd, seen_ids, min(remaining_cmd, len(pool_cmd))))

        history = []
        if kernel_hist:
            history.extend(_prefer_unseen(kernel_hist, seen_ids, 1))
        remaining_hist = max(0, min(3, len(HISTORY_QUESTIONS)) - len(history))
        pool_hist = [q for q in other_hist if q not in history]
        if pool_hist and remaining_hist > 0:
            history.extend(_prefer_unseen(pool_hist, seen_ids, min(remaining_hist, len(pool_hist))))

        session3 = _prefer_unseen(SESSION3_IMAGE_QUESTIONS, seen_ids, min(4, len(SESSION3_IMAGE_QUESTIONS)))
        images = _prefer_unseen(IMAGE_QUESTIONS, seen_ids, min(2, len(IMAGE_QUESTIONS)))
        cat_shell = [q for q in SHELL_EXERCISES if q["id"].startswith("shell_cat_")]
        df_shell = [q for q in SHELL_EXERCISES if q["id"].startswith("shell_df_")]
        mv_shell = [q for q in SHELL_EXERCISES if q["id"].startswith("shell_mv_")]
        other_shell = [
            q
            for q in SHELL_EXERCISES
            if not q["id"].startswith("shell_cat_")
            and not q["id"].startswith("shell_df_")
            and not q["id"].startswith("shell_mv_")
        ]
        shell = []
        if cat_shell:
            shell.extend(_prefer_unseen(cat_shell, seen_ids, 1))
        if df_shell:
            shell.extend(_prefer_unseen(df_shell, seen_ids, 1))
        if mv_shell:
            shell.extend(_prefer_unseen(mv_shell, seen_ids, 1))
        remaining_shell = max(0, min(8, len(SHELL_EXERCISES)) - len(shell))
        pool_shell = [q for q in other_shell if q not in shell]
        if pool_shell and remaining_shell > 0:
            shell.extend(_prefer_unseen(pool_shell, seen_ids, min(remaining_shell, len(pool_shell))))
        items = command + history + session3 + images + shell
    randomized_items: List[Dict] = []
    for base_item in items:
        item = copy.deepcopy(base_item)
        if item.get("type") == "mcq" and isinstance(item.get("choices"), list):
            correct_idx = int(item.get("correct", 0))
            pairs = list(enumerate(item["choices"]))
            random.shuffle(pairs)
            item["choices"] = [choice for _, choice in pairs]
            for new_idx, (old_idx, _) in enumerate(pairs):
                if old_idx == correct_idx:
                    item["correct"] = new_idx
                    break
        randomized_items.append(item)
    random.shuffle(randomized_items)

    if student_key and conn is not None:
        now = utcnow_iso()
        for it in randomized_items:
            iid = (it.get("id") or "").strip()
            if not iid:
                continue
            conn.execute(
                """
                INSERT OR REPLACE INTO student_item_history (student_key, item_id, seen_at)
                VALUES (?, ?, ?)
                """,
                (student_key, iid, now),
            )
    return randomized_items


def serialize_item(item: dict) -> dict:
    if item["type"] == "mcq":
        return {
            "id": item["id"],
            "type": "mcq",
            "prompt": item["prompt"],
            "choices": item["choices"],
        }
    if item["type"] == "image_click":
        return {
            "id": item["id"],
            "type": "image_click",
            "prompt": item["prompt"],
            "image_url": item["image_url"],
            "hotspots": item["hotspots"],
        }
    return {
        "id": item["id"],
        "type": "shell",
        "title": item["title"],
        "prompt": item["prompt"],
        "terminal_hint": item["terminal_hint"],
    }


def evaluate_item(item: dict, answer: str, command_trace: Optional[List[str]] = None) -> Tuple[bool, str, str]:
    clean_answer = (answer or "").strip()
    clean_trace = [str(x).strip() for x in (command_trace or []) if str(x).strip()]
    if item["type"] == "mcq":
        try:
            idx = int(clean_answer)
        except ValueError:
            return False, "Seleccion invalida", str(item["correct"])
        is_correct = idx == item["correct"]
        feedback = "Correcto" if is_correct else "Incorrecto"
        return is_correct, feedback, str(item["correct"])
    if item["type"] == "image_click":
        is_correct = clean_answer == item["correct"]
        feedback = "Correcto" if is_correct else f"Incorrecto. Esperado: {item['expected']}"
        return is_correct, feedback, item["correct"]

    matched = any(re.match(pattern, clean_answer) for pattern in item["accepted"])
    if not matched and clean_trace:
        matched = any(any(re.match(pattern, cmd) for pattern in item["accepted"]) for cmd in clean_trace)

    # Algunos ejercicios aceptan una secuencia de comandos valida en vez de una sola linea.
    if not matched and item.get("id") == "shell_mkdir_copy_subdir" and clean_trace:
        made_dir = any(re.match(r"^mkdir\s+respaldo$", cmd) for cmd in clean_trace)
        copied = any(
            re.match(r"^cp\s+(\.\./)?notas\.txt\s+(\./)?$", cmd)
            or re.match(r"^cp\s+(\.\./)?notas\.txt\s+respaldo/?$", cmd)
            for cmd in clean_trace
        )
        matched = made_dir and copied

    if not matched and item.get("id") == "shell_grep_tail" and clean_trace:
        did_cat = any(re.match(r"^cat\s+/var/log/syslog$", cmd) for cmd in clean_trace)
        did_grep = any(
            re.match(r"^grep\s+(-i\s+)?error(\s+/var/log/syslog)?$", cmd)
            or re.match(r"^grep\s+(-i\s+)?error\s+/var/log/syslog$", cmd)
            for cmd in clean_trace
        )
        did_tail20 = any(re.match(r"^tail\s+-n\s+20(\s+/var/log/syslog)?$", cmd) for cmd in clean_trace)
        matched = (did_cat and did_grep) or (did_grep and did_tail20)

    if not matched and item.get("id") == "cmd_user_passwd" and clean_trace:
        did_passwd = any(re.match(r"^(sudo\s+)?passwd\s+operador$", cmd) for cmd in clean_trace)
        did_verify = any(
            re.match(r"^(sudo\s+)?grep\s+operador\s+/etc/shadow$", cmd)
            or re.match(r"^(sudo\s+)?cat\s+/etc/shadow$", cmd)
            or re.match(r"^(sudo\s+)?more\s+/etc/shadow$", cmd)
            for cmd in clean_trace
        )
        matched = did_passwd and did_verify

    if not matched and item.get("id") == "shell_shadow_hashes" and clean_trace:
        did_show = any(
            re.match(r"^(sudo\s+)?cat\s+(/etc/shadow|shadow)$", cmd)
            or re.match(r"^(sudo\s+)?more\s+(/etc/shadow|shadow)$", cmd)
            for cmd in clean_trace
        )
        did_filter = any(
            re.match(r"^(sudo\s+)?grep\s+operador\s+(/etc/shadow|shadow)$", cmd)
            for cmd in clean_trace
        )
        matched = did_show and did_filter

    feedback = item["success_output"] if matched else f"Comando no valido para la tarea. Esperado: {item['expected']}"
    return matched, feedback, item["expected"]


def get_session_payload(conn: sqlite3.Connection, token: str) -> Optional[Dict]:
    row = conn.execute("SELECT * FROM exam_sessions WHERE session_token = ?", (token,)).fetchone()
    if not row:
        return None
    payload = json.loads(row["exam_payload"])
    return {
        "row": row,
        "items": payload,
    }


def recalculate_score(conn: sqlite3.Connection, token: str) -> int:
    row = conn.execute(
        "SELECT COALESCE(SUM(is_correct), 0) AS score FROM responses WHERE session_token = ?",
        (token,),
    ).fetchone()
    return int(row["score"]) if row else 0


def ensure_timing_row(conn: sqlite3.Connection, token: str, item_index: int) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO question_timing (session_token, item_index, seconds_spent, last_entered_at)
        VALUES (?, ?, 0, NULL)
        """,
        (token, item_index),
    )


def enter_question(conn: sqlite3.Connection, token: str, item_index: int, at_iso: Optional[str] = None) -> None:
    ts = at_iso or utcnow_iso()
    ensure_timing_row(conn, token, item_index)
    conn.execute(
        """
        UPDATE question_timing
        SET last_entered_at = ?
        WHERE session_token = ? AND item_index = ?
        """,
        (ts, token, item_index),
    )


def checkpoint_question(conn: sqlite3.Connection, token: str, item_index: int, at_iso: Optional[str] = None) -> None:
    ts = at_iso or utcnow_iso()
    ensure_timing_row(conn, token, item_index)
    row = conn.execute(
        "SELECT seconds_spent, last_entered_at FROM question_timing WHERE session_token = ? AND item_index = ?",
        (token, item_index),
    ).fetchone()
    if not row:
        return
    if row["last_entered_at"]:
        delta = elapsed_seconds(row["last_entered_at"], ts)
        conn.execute(
            """
            UPDATE question_timing
            SET seconds_spent = seconds_spent + ?, last_entered_at = ?
            WHERE session_token = ? AND item_index = ?
            """,
            (delta, ts, token, item_index),
        )
    else:
        conn.execute(
            """
            UPDATE question_timing
            SET last_entered_at = ?
            WHERE session_token = ? AND item_index = ?
            """,
            (ts, token, item_index),
        )


def leave_question(conn: sqlite3.Connection, token: str, item_index: int, at_iso: Optional[str] = None) -> None:
    ts = at_iso or utcnow_iso()
    ensure_timing_row(conn, token, item_index)
    row = conn.execute(
        "SELECT last_entered_at FROM question_timing WHERE session_token = ? AND item_index = ?",
        (token, item_index),
    ).fetchone()
    if row and row["last_entered_at"]:
        delta = elapsed_seconds(row["last_entered_at"], ts)
        conn.execute(
            """
            UPDATE question_timing
            SET seconds_spent = seconds_spent + ?, last_entered_at = NULL
            WHERE session_token = ? AND item_index = ?
            """,
            (delta, token, item_index),
        )


TOPIC_PRACTICE_HINTS = {
    "Procesos y rendimiento": "Practica top, htop, ps aux, kill -9 y analiza CPU/Mem/Swap.",
    "Redes": "Practica ip a, ip route, ping, ss -tulnp y curl a endpoints internos.",
    "Permisos y propiedad": "Practica chmod numerico/simbolico, chown y validacion con ls -l.",
    "Logs y diagnostico": "Practica grep/tail/head sobre /var/log/syslog y /var/log/auth.log.",
    "Gestion de paquetes": "Practica apt update, apt install, dpkg -l y apt remove.",
    "Respaldo y restauracion": "Practica tar -czf, tar -xzf y validacion de contenido.",
    "Archivos y filesystem": "Practica find, cat, df, du, mv y rutas absolutas/relativas.",
    "Usuarios y cuentas": "Practica whoami, id, groups, last, passwd y /etc/shadow.",
    "Firewall y seguridad": "Practica ufw status, habilitar/deshabilitar y ver reglas.",
    "Comandos de shell": "Practica sintaxis exacta y lectura cuidadosa de flags.",
}


def expected_answer_text(item: Dict, include_correct_answer: bool = True) -> str:
    if not include_correct_answer:
        return ""
    itype = item.get("type", "")
    if itype == "mcq":
        try:
            idx = int(item.get("correct", 0))
        except Exception:
            idx = 0
        choices = item.get("choices") or []
        if isinstance(choices, list) and 0 <= idx < len(choices):
            return str(choices[idx])
        return str(idx)
    if itype == "image_click":
        return str(item.get("expected") or item.get("correct") or "")
    return str(item.get("expected") or "")


def session_summary(conn: sqlite3.Connection, token: str, include_correct_answer: bool = True, mark_viewed: bool = False) -> Optional[Dict]:
    data = get_session_payload(conn, token)
    if not data:
        return None
    row = data["row"]
    if not int(row["completed"] or 0):
        return {"error": "El examen aun no ha finalizado"}

    if mark_viewed:
        conn.execute(
            "UPDATE exam_sessions SET summary_viewed_at = ? WHERE session_token = ?",
            (utcnow_iso(), token),
        )

    items = data["items"]
    responses = conn.execute(
        """
        SELECT item_index, item_id, item_type, user_answer, is_correct, expected, submitted_at
        FROM responses
        WHERE session_token = ?
        ORDER BY item_index ASC
        """,
        (token,),
    ).fetchall()
    response_by_idx = {int(r["item_index"]): dict(r) for r in responses}

    timings = conn.execute(
        """
        SELECT item_index, seconds_spent, last_entered_at
        FROM question_timing
        WHERE session_token = ?
        ORDER BY item_index ASC
        """,
        (token,),
    ).fetchall()
    now_iso = utcnow_iso()
    time_by_idx: Dict[int, int] = {}
    for t in timings:
        idx = int(t["item_index"])
        extra = elapsed_seconds(t["last_entered_at"], now_iso) if t["last_entered_at"] else 0
        time_by_idx[idx] = int(float(t["seconds_spent"] or 0) + extra)

    per_question = []
    topic_stats: Dict[str, Dict[str, float]] = defaultdict(lambda: {"total": 0, "correct": 0, "seconds": 0})
    for idx, item in enumerate(items):
        resp = response_by_idx.get(idx, {})
        is_correct = bool(int(resp.get("is_correct") or 0))
        topic = topic_for_item_id(str(item.get("id") or ""))
        seconds_spent = int(time_by_idx.get(idx, 0))
        topic_stats[topic]["total"] += 1
        topic_stats[topic]["correct"] += 1 if is_correct else 0
        topic_stats[topic]["seconds"] += seconds_spent
        per_question.append(
            {
                "question_number": idx + 1,
                "item_id": str(item.get("id") or ""),
                "topic": topic,
                "prompt": str(item.get("prompt") or ""),
                "status": "Correcta" if is_correct else "Incorrecta",
                "is_correct": is_correct,
                "your_answer": str(resp.get("user_answer") or ""),
                "correct_answer": expected_answer_text(item, include_correct_answer=include_correct_answer),
                "seconds_spent": seconds_spent,
            }
        )

    topic_rows = []
    for topic, st in topic_stats.items():
        total = int(st["total"])
        correct = int(st["correct"])
        seconds = int(st["seconds"])
        precision = (correct / total * 100.0) if total else 0.0
        avg_time = (seconds / total) if total else 0.0
        topic_rows.append(
            {
                "topic": topic,
                "total": total,
                "correct": correct,
                "precision_pct": round(precision, 2),
                "avg_seconds": round(avg_time, 2),
                "recommendation": TOPIC_PRACTICE_HINTS.get(topic, "Practica guiada en este tema."),
            }
        )

    strengths = sorted(topic_rows, key=lambda x: (x["precision_pct"], x["total"]), reverse=True)[:3]
    weaknesses = sorted(topic_rows, key=lambda x: (x["precision_pct"], -x["avg_seconds"], -x["total"]))[:3]
    recommendations = [x["recommendation"] for x in weaknesses]

    return {
        "session_token": token,
        "student_name": row["student_name"],
        "student_email": row["student_email"],
        "score": int(row["score"] or 0),
        "total": int(row["total_items"] or 0),
        "elapsed_seconds": elapsed_seconds(row["started_at"], row["finished_at"]),
        "summary_viewed_at": row["summary_viewed_at"],
        "show_correct_answers": bool(include_correct_answer),
        "questions": per_question,
        "topic_summary": topic_rows,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "practice_recommendations": recommendations,
    }


def create_app() -> Flask:
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config["SECRET_KEY"] = os.environ.get("CURSO_LINUX_SECRET", "curso-linux-dev-key")
    app.config["TEACHER_USER"] = os.environ.get("CURSO_LINUX_TEACHER_USER", "teacher")
    app.config["TEACHER_PASSWORD"] = os.environ.get("CURSO_LINUX_TEACHER_PASSWORD", "ikusi2026")
    app.config["SHOW_CORRECT_ANSWERS_TO_STUDENT"] = str(
        os.environ.get("SHOW_CORRECT_ANSWERS_TO_STUDENT", "1")
    ).strip().lower() not in {"0", "false", "no", "off"}
    app.config["SHOW_STUDENT_RESULTS_TO_STUDENT"] = str(
        os.environ.get("SHOW_STUDENT_RESULTS_TO_STUDENT", "1")
    ).strip().lower() not in {"0", "false", "no", "off"}
    init_db()
    with get_db() as conn:
        set_bool_setting(
            conn,
            "show_student_results_to_student",
            bool(app.config["SHOW_STUDENT_RESULTS_TO_STUDENT"]),
        )

    def require_teacher_auth() -> Optional[Response]:
        auth = request.authorization
        user_ok = bool(auth and compare_digest(auth.username or "", app.config["TEACHER_USER"]))
        pass_ok = bool(auth and compare_digest(auth.password or "", app.config["TEACHER_PASSWORD"]))
        if user_ok and pass_ok:
            return None
        return Response(
            "Autenticacion requerida",
            401,
            {"WWW-Authenticate": 'Basic realm="CursoLinux-Teacher"'},
        )

    @app.get("/")
    def index():
        return render_template("cover.html", show_teacher_link=False)

    @app.get("/alumno")
    def student_page():
        return render_template("student_select.html", show_teacher_link=False)

    @app.post("/start")
    def start_exam():
        student_name = request.form.get("student_name", "").strip()
        student_email = normalize_email(request.form.get("student_email", ""))
        if not student_name:
            return render_template("student_select.html", error="Ingresa tu nombre completo", show_teacher_link=False)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", student_email):
            return render_template("student_select.html", error="Ingresa un correo valido", show_teacher_link=False)

        with get_db() as conn:
            assigned_level = get_student_level(conn, student_email, default_level=1)
            existing = conn.execute(
                """
                SELECT session_token
                FROM exam_sessions
                WHERE student_email = ? AND completed = 0
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (student_email,),
            ).fetchone()
            if existing:
                return redirect(url_for("exam_page", token=existing["session_token"]))

            token = str(uuid.uuid4())
            student_key = student_key_for_cycle(student_name, student_email)
            items = build_exam(student_key=student_key, conn=conn, exam_level=assigned_level)
            conn.execute(
                """
                INSERT INTO exam_sessions
                (session_token, student_name, student_email, started_at, total_items, exam_level, exam_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (token, student_name, student_email, utcnow_iso(), len(items), int(assigned_level), json.dumps(items)),
            )
            enter_question(conn, token, 0)
        return redirect(url_for("exam_page", token=token))

    @app.get("/exam/<token>")
    def exam_page(token: str):
        with get_db() as conn:
            data = get_session_payload(conn, token)
            if not data:
                return redirect(url_for("student_page"))
            row = data["row"]
        return render_template("exam.html", token=token, student_name=row["student_name"], show_teacher_link=False)

    @app.get("/api/exam/<token>/state")
    def exam_state(token: str):
        with get_db() as conn:
            data = get_session_payload(conn, token)
            if not data:
                return jsonify({"error": "Sesion no encontrada"}), 404

            row = data["row"]
            items = data["items"]
            idx = row["current_index"]

            if row["completed"]:
                can_view_results = get_bool_setting(
                    conn,
                    "show_student_results_to_student",
                    bool(app.config["SHOW_STUDENT_RESULTS_TO_STUDENT"]),
                )
                return jsonify(
                    {
                        "completed": True,
                        "score": row["score"],
                        "total": row["total_items"],
                        "show_student_results": bool(can_view_results),
                        "student_name": row["student_name"],
                        "index": row["total_items"],
                        "started_at": row["started_at"],
                        "finished_at": row["finished_at"],
                        "elapsed_seconds": elapsed_seconds(row["started_at"], row["finished_at"]),
                    }
                )

            current_item = serialize_item(items[idx])
            ensure_timing_row(conn, token, idx)
            timing_row = conn.execute(
                "SELECT last_entered_at FROM question_timing WHERE session_token = ? AND item_index = ?",
                (token, idx),
            ).fetchone()
            if timing_row and not timing_row["last_entered_at"]:
                enter_question(conn, token, idx)
            prev_resp = conn.execute(
                "SELECT user_answer, distro_guess, command_trace, extra_text FROM responses WHERE session_token = ? AND item_index = ?",
                (token, idx),
            ).fetchone()
            existing_trace = []
            if prev_resp and prev_resp["command_trace"]:
                try:
                    trace_candidate = json.loads(prev_resp["command_trace"])
                    if isinstance(trace_candidate, list):
                        existing_trace = [str(x) for x in trace_candidate][:100]
                except Exception:
                    existing_trace = []
            answered_rows = conn.execute(
                "SELECT item_index FROM responses WHERE session_token = ?",
                (token,),
            ).fetchall()
            return jsonify(
                {
                    "completed": False,
                    "student_name": row["student_name"],
                    "index": idx + 1,
                    "max_reached_index": max(int(row["max_reached_index"] or 0), idx) + 1,
                    "total": row["total_items"],
                    "item": current_item,
                    "can_go_prev": idx > 0,
                    "existing_answer": prev_resp["user_answer"] if prev_resp else "",
                    "existing_distro_guess": prev_resp["distro_guess"] if prev_resp else "",
                    "existing_command_trace": existing_trace,
                    "existing_extra_text": prev_resp["extra_text"] if prev_resp else "",
                    "started_at": row["started_at"],
                    "elapsed_seconds": elapsed_seconds(row["started_at"], None),
                    "answered_indices": [int(r["item_index"]) for r in answered_rows],
                }
            )

    @app.get("/api/exam/<token>/summary")
    def exam_summary(token: str):
        with get_db() as conn:
            can_view_results = get_bool_setting(
                conn,
                "show_student_results_to_student",
                bool(app.config["SHOW_STUDENT_RESULTS_TO_STUDENT"]),
            )
            if not can_view_results:
                return jsonify({"error": "Resultados ocultos por el maestro"}), 403
            summary = session_summary(
                conn,
                token,
                include_correct_answer=bool(app.config["SHOW_CORRECT_ANSWERS_TO_STUDENT"]),
                mark_viewed=True,
            )
            if not summary:
                return jsonify({"error": "Sesion no encontrada"}), 404
            if summary.get("error"):
                return jsonify({"error": summary["error"]}), 400
            return jsonify(summary)

    @app.post("/api/exam/<token>/prev")
    def prev_question(token: str):
        with get_db() as conn:
            data = get_session_payload(conn, token)
            if not data:
                return jsonify({"error": "Sesion no encontrada"}), 404

            row = data["row"]
            current_idx = int(row["current_index"])
            new_idx = current_idx - 1 if current_idx > 0 else 0
            leave_question(conn, token, current_idx)
            conn.execute(
                """
                UPDATE exam_sessions
                SET current_index = ?, completed = 0
                WHERE session_token = ?
                """,
                (new_idx, token),
            )
            enter_question(conn, token, new_idx)
        return jsonify({"ok": True, "index": new_idx + 1})

    @app.post("/api/exam/<token>/goto")
    def goto_question(token: str):
        req = request.get_json(force=True, silent=True) or {}
        target_q = int(req.get("question", 0))
        with get_db() as conn:
            data = get_session_payload(conn, token)
            if not data:
                return jsonify({"error": "Sesion no encontrada"}), 404
            row = data["row"]
            total = int(row["total_items"])
            if target_q < 1 or target_q > total:
                return jsonify({"error": "Numero de pregunta invalido"}), 400
            current_idx = int(row["current_index"])
            max_reached = max(int(row["max_reached_index"] or 0), current_idx)
            if target_q > (max_reached + 1):
                return jsonify({"error": "No puedes avanzar desde el menu de preguntas"}), 400
            new_idx = target_q - 1
            leave_question(conn, token, current_idx)
            conn.execute(
                """
                UPDATE exam_sessions
                SET current_index = ?, completed = 0
                WHERE session_token = ?
                """,
                (new_idx, token),
            )
            enter_question(conn, token, new_idx)
        return jsonify({"ok": True, "index": target_q})

    @app.post("/api/exam/<token>/heartbeat")
    def exam_heartbeat(token: str):
        with get_db() as conn:
            data = get_session_payload(conn, token)
            if not data:
                return jsonify({"error": "Sesion no encontrada"}), 404
            row = data["row"]
            if row["completed"]:
                return jsonify({"ok": True, "completed": True})
            current_idx = int(row["current_index"])
            checkpoint_question(conn, token, current_idx)
        return jsonify({"ok": True})

    @app.post("/api/exam/<token>/answer")
    def submit_answer(token: str):
        req = request.get_json(force=True)
        answer = (req.get("answer") or "").strip()
        distro_guess = (req.get("distro_guess") or "").strip()
        extra_text = (req.get("extra_text") or "").strip()
        command_trace_raw = req.get("command_trace")
        command_trace_list: List[str] = []
        if isinstance(command_trace_raw, list):
            command_trace_list = [str(x).strip() for x in command_trace_raw if str(x).strip()][:120]
        command_trace_json = json.dumps(command_trace_list, ensure_ascii=False)

        with get_db() as conn:
            data = get_session_payload(conn, token)
            if not data:
                return jsonify({"error": "Sesion no encontrada"}), 404

            row = data["row"]
            items = data["items"]

            idx = row["current_index"]
            item = items[idx]

            exists = conn.execute(
                "SELECT id FROM responses WHERE session_token = ? AND item_index = ?",
                (token, idx),
            ).fetchone()

            is_correct, feedback, expected = evaluate_item(item, answer, command_trace_list)
            attempt_no_row = conn.execute(
                "SELECT COALESCE(MAX(attempt_no), 0) AS n FROM response_attempts WHERE session_token = ? AND item_index = ?",
                (token, idx),
            ).fetchone()
            attempt_no = int((attempt_no_row["n"] if attempt_no_row else 0) or 0) + 1
            conn.execute(
                """
                INSERT INTO response_attempts (session_token, item_index, item_id, attempt_no, user_answer, is_correct, submitted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (token, idx, item["id"], attempt_no, answer, 1 if is_correct else 0, utcnow_iso()),
            )
            next_index = idx + 1
            completed = 1 if next_index >= row["total_items"] else 0
            max_reached = int(row["max_reached_index"] or 0)
            if not completed:
                max_reached = max(max_reached, next_index)
            else:
                max_reached = max(max_reached, idx)

            if exists:
                conn.execute(
                    """
                    UPDATE responses
                    SET user_answer = ?, distro_guess = ?, command_trace = ?, extra_text = ?, is_correct = ?, expected = ?, submitted_at = ?
                    WHERE session_token = ? AND item_index = ?
                    """,
                    (answer, distro_guess, command_trace_json, extra_text, 1 if is_correct else 0, expected, utcnow_iso(), token, idx),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO responses
                    (session_token, item_index, item_id, item_type, prompt, user_answer, distro_guess, command_trace, extra_text, is_correct, expected, submitted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        token,
                        idx,
                        item["id"],
                        item["type"],
                        item["prompt"],
                        answer,
                        distro_guess,
                        command_trace_json,
                        extra_text,
                        1 if is_correct else 0,
                        expected,
                        utcnow_iso(),
                    ),
                )

            new_score = recalculate_score(conn, token)
            leave_question(conn, token, idx)
            if not completed:
                enter_question(conn, token, next_index)

            conn.execute(
                """
                UPDATE exam_sessions
                SET current_index = ?, max_reached_index = ?, score = ?, completed = ?, finished_at = CASE WHEN ? = 1 THEN ? ELSE finished_at END
                WHERE session_token = ?
                """,
                (next_index, max_reached, new_score, completed, completed, utcnow_iso(), token),
            )

            return jsonify(
                {
                    "is_correct": is_correct,
                    "feedback": feedback,
                    "completed": bool(completed),
                    "score": new_score,
                    "total": row["total_items"],
                }
            )

    @app.get("/teacher")
    def teacher_page():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        return render_template("teacher.html", show_teacher_link=True, page_class="teacher-wide", teacher_nav_mode=True)

    @app.get("/teacher/students")
    def teacher_students_page():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        return render_template("teacher_students.html", show_teacher_link=True, teacher_nav_mode=True)

    @app.get("/api/teacher/settings")
    def teacher_settings_get():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            show_results = get_bool_setting(
                conn,
                "show_student_results_to_student",
                bool(app.config["SHOW_STUDENT_RESULTS_TO_STUDENT"]),
            )
        return jsonify({"show_student_results_to_student": bool(show_results)})

    @app.post("/api/teacher/settings")
    def teacher_settings_set():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        req = request.get_json(force=True, silent=True) or {}
        raw = req.get("show_student_results_to_student")
        if isinstance(raw, bool):
            show_results = raw
        elif str(raw).strip().lower() in {"1", "true", "yes", "si", "on"}:
            show_results = True
        elif str(raw).strip().lower() in {"0", "false", "no", "off"}:
            show_results = False
        else:
            return jsonify({"error": "Valor invalido para show_student_results_to_student"}), 400
        with get_db() as conn:
            set_bool_setting(conn, "show_student_results_to_student", bool(show_results))
        return jsonify({"ok": True, "show_student_results_to_student": bool(show_results)})

    @app.post("/api/teacher/student-level")
    def teacher_set_student_level():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        req = request.get_json(force=True, silent=True) or {}
        student_email = normalize_email(req.get("student_email") or "")
        level_raw = req.get("exam_level")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", student_email):
            return jsonify({"error": "Correo invalido"}), 400
        try:
            exam_level = int(level_raw)
        except Exception:
            return jsonify({"error": "Nivel invalido"}), 400
        exam_level = 2 if exam_level >= 2 else 1
        with get_db() as conn:
            applied_level = set_student_level(conn, student_email, exam_level)
            active = conn.execute(
                "SELECT COUNT(*) AS c FROM exam_sessions WHERE student_email = ? AND completed = 0",
                (student_email,),
            ).fetchone()
        return jsonify(
            {
                "ok": True,
                "student_email": student_email,
                "exam_level": int(applied_level),
                "active_sessions": int((active["c"] if active else 0) or 0),
                "applies_next_attempt": True,
            }
        )

    @app.get("/teacher/distros")
    def teacher_distros_page():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            row = conn.execute("SELECT COALESCE(MAX(total_items), 0) AS max_total FROM exam_sessions").fetchone()
        default_total = len(build_exam())
        max_total = int(row["max_total"] or 0) if row else 0
        total_questions = max(default_total, max_total, 1)
        distro_rows = []
        for qn in range(1, total_questions + 1):
            distro = DISTRO_ROTATION[(qn - 1) % len(DISTRO_ROTATION)]
            distro_rows.append(
                {
                    "question_number": qn,
                    "name": distro["name"],
                    "image_name": distro["image"],
                    "image_url": url_for("static", filename=f"images/distros/{distro['image']}"),
                }
            )
        return render_template(
            "teacher_distros.html",
            rows=distro_rows,
            total_questions=total_questions,
            rotation_size=len(DISTRO_ROTATION),
            show_teacher_link=True,
            teacher_nav_mode=True,
        )

    @app.get("/api/teacher/students")
    def teacher_students():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT student_name, student_email, started_at, completed
                FROM exam_sessions
                ORDER BY started_at DESC
                """
            ).fetchall()
        agg: Dict[str, Dict] = {}
        for r in rows:
            d = dict(r)
            skey = student_key_for_cycle(d.get("student_name", ""), d.get("student_email", ""))
            if skey not in agg:
                agg[skey] = {
                    "student_key": skey,
                    "student_name": d.get("student_name", ""),
                    "student_email": d.get("student_email", ""),
                    "attempts_total": 0,
                    "attempts_completed": 0,
                    "last_started_at": d.get("started_at", ""),
                }
            agg[skey]["attempts_total"] += 1
            if d.get("completed"):
                agg[skey]["attempts_completed"] += 1
        data = sorted(
            agg.values(),
            key=lambda x: ((x.get("student_name") or "").lower(), (x.get("student_email") or "").lower()),
        )
        return jsonify({"students": data})

    @app.get("/api/teacher/student/<path:student_key>")
    def teacher_student_detail(student_key: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        wanted = (student_key or "").strip()
        if not wanted:
            return jsonify({"error": "Alumno invalido"}), 400

        with get_db() as conn:
            all_sessions = conn.execute(
                """
                SELECT *
                FROM exam_sessions
                ORDER BY started_at ASC
                """
            ).fetchall()

            sessions = [dict(s) for s in all_sessions if student_key_for_cycle(s["student_name"], s["student_email"]) == wanted]
            if not sessions:
                return jsonify({"error": "Alumno no encontrado"}), 404

            tokens = [s["session_token"] for s in sessions]
            placeholders = ",".join(["?"] * len(tokens))

            responses_raw = conn.execute(
                f"""
                SELECT r.session_token, r.item_index, r.item_id, r.item_type, r.prompt, r.user_answer, r.distro_guess, r.command_trace, r.extra_text, r.is_correct, r.expected, r.submitted_at
                FROM responses r
                WHERE r.session_token IN ({placeholders})
                ORDER BY r.submitted_at ASC
                """,
                tokens,
            ).fetchall()

            timings_raw = conn.execute(
                f"""
                SELECT t.session_token, t.item_index, t.seconds_spent, t.last_entered_at
                FROM question_timing t
                WHERE t.session_token IN ({placeholders})
                ORDER BY t.session_token ASC, t.item_index ASC
                """,
                tokens,
            ).fetchall()

            attempts_raw = conn.execute(
                f"""
                SELECT session_token, item_index, attempt_no, is_correct
                FROM response_attempts
                WHERE session_token IN ({placeholders})
                ORDER BY session_token, item_index, attempt_no
                """,
                tokens,
            ).fetchall()

        now_iso = utcnow_iso()
        topic_stats: Dict[str, Dict] = defaultdict(lambda: {"total": 0, "correct": 0, "times": [], "syntax": 0, "conceptual": 0})
        timing_map: Dict[Tuple[str, int], int] = {}
        timing_rows = []
        for t in timings_raw:
            d = dict(t)
            extra = elapsed_seconds(d["last_entered_at"], now_iso) if d.get("last_entered_at") else 0
            d["seconds_total"] = int(float(d.get("seconds_spent") or 0) + extra)
            timing_map[(d["session_token"], int(d["item_index"]))] = d["seconds_total"]
            timing_rows.append(d)

        responses = []
        correct = 0
        for r in responses_raw:
            d = dict(r)
            item_id = d.get("item_id", "")
            topic = topic_for_item_id(item_id)
            is_correct = int(d.get("is_correct") or 0) == 1
            sec = timing_map.get((d.get("session_token", ""), int(d.get("item_index") or 0)))
            topic_stats[topic]["total"] += 1
            topic_stats[topic]["correct"] += 1 if is_correct else 0
            if sec is not None:
                topic_stats[topic]["times"].append(sec)

            trace_list = []
            trace_raw = d.get("command_trace")
            if isinstance(trace_raw, str) and trace_raw:
                try:
                    parsed = json.loads(trace_raw)
                    if isinstance(parsed, list):
                        trace_list = [str(x) for x in parsed]
                except Exception:
                    trace_list = []
            sev = classify_error_severity(
                d.get("item_type", ""),
                item_id,
                d.get("user_answer", ""),
                d.get("expected", ""),
                trace_list,
            ) if not is_correct else "none"
            if sev == "sintaxis":
                topic_stats[topic]["syntax"] += 1
            elif sev == "conceptual":
                topic_stats[topic]["conceptual"] += 1
            if is_correct:
                correct += 1
            d["topic"] = topic
            d["error_severity"] = sev
            d["command_trace_list"] = trace_list
            responses.append(d)

        precision_by_topic = []
        median_time_by_topic = []
        sev_con = 0
        sev_syn = 0
        for topic, st in topic_stats.items():
            total = int(st["total"] or 0)
            ok = int(st["correct"] or 0)
            precision_by_topic.append(
                {"topic": topic, "precision_pct": round((ok / total * 100.0) if total else 0.0, 2), "total": total}
            )
            median_time_by_topic.append(
                {"topic": topic, "median_seconds": int(statistics.median(st["times"])) if st["times"] else 0}
            )
            sev_con += int(st["conceptual"] or 0)
            sev_syn += int(st["syntax"] or 0)
        precision_by_topic.sort(key=lambda x: (x["precision_pct"], -x["total"]))
        median_time_by_topic.sort(key=lambda x: x["median_seconds"], reverse=True)

        attempt_groups: Dict[Tuple[str, int], List[Dict]] = defaultdict(list)
        for a in attempts_raw:
            dd = dict(a)
            attempt_groups[(dd["session_token"], int(dd["item_index"]))].append(dd)
        second_fix_den = 0
        second_fix_ok = 0
        for _, group in attempt_groups.items():
            group = sorted(group, key=lambda x: int(x.get("attempt_no") or 0))
            if len(group) < 2:
                continue
            if int(group[0].get("is_correct") or 0) == 0:
                second_fix_den += 1
                if int(group[1].get("is_correct") or 0) == 1:
                    second_fix_ok += 1

        sessions_sorted = sorted(sessions, key=lambda x: x.get("started_at") or "")
        attempts_timeline = []
        for s in sessions_sorted:
            total_items = max(1, int(s.get("total_items") or 0))
            score = int(s.get("score") or 0)
            attempts_timeline.append(
                {
                    "session_token": s["session_token"],
                    "started_at": s.get("started_at"),
                    "finished_at": s.get("finished_at"),
                    "completed": bool(s.get("completed")),
                    "resets_count": int(s.get("resets_count") or 0),
                    "elapsed_seconds": elapsed_seconds(s.get("started_at"), s.get("finished_at")),
                    "score": score,
                    "total_items": int(s.get("total_items") or 0),
                    "score_pct": round(score / total_items * 100.0, 2),
                }
            )

        latest_session = sessions_sorted[-1]
        latest_token = latest_session["session_token"]
        latest_response_by_index: Dict[int, Dict] = {}
        for r in responses:
            if r.get("session_token") != latest_token:
                continue
            idx = int(r.get("item_index") or 0)
            latest_response_by_index[idx] = r
        latest_timing = [
            {
                "question_number": int(t["item_index"]) + 1,
                "item_index": int(t["item_index"]),
                "item_id": (latest_response_by_index.get(int(t["item_index"])) or {}).get("item_id", ""),
                "topic": (latest_response_by_index.get(int(t["item_index"])) or {}).get("topic", DEFAULT_TOPIC),
                "prompt": (latest_response_by_index.get(int(t["item_index"])) or {}).get("prompt", ""),
                "seconds_total": int(t["seconds_total"]),
            }
            for t in timing_rows
            if t["session_token"] == latest_token
        ]
        latest_timing.sort(key=lambda x: x["question_number"])

        total_responses = len(responses)
        wrong_rate = (1.0 - (correct / total_responses)) if total_responses else 1.0
        all_times = [int(t["seconds_total"]) for t in timing_rows]
        syntax_err = sev_syn
        conceptual_err = sev_con
        err_total = max(1, syntax_err + conceptual_err)
        feature_rows = [
            {
                "student_key": wanted,
                "wrong_rate": wrong_rate,
                "median_time_topic": float(statistics.median(all_times)) if all_times else 0.0,
                "resets": int(sum(int(s.get("resets_count") or 0) for s in sessions_sorted)),
                "dropouts": int(sum(1 for s in sessions_sorted if (not s.get("completed")) and elapsed_seconds(s.get("started_at"), s.get("finished_at")) >= 600)),
                "syntax_error_ratio": float(syntax_err) / float(err_total),
            }
        ]
        pred = build_ml_risk(feature_rows).get(wanted, {"risk_prob": 0.0, "risk_level": "bajo", "model": "heuristic"})

        return jsonify(
            {
                "student": {
                    "student_key": wanted,
                    "student_name": latest_session.get("student_name", ""),
                    "student_email": latest_session.get("student_email", ""),
                },
                "attempts_timeline": attempts_timeline,
                "latest_question_timing": latest_timing,
                "kpis": {
                    "precision_by_topic": precision_by_topic,
                    "median_time_by_topic": median_time_by_topic,
                    "second_attempt_fix_rate_pct": round((second_fix_ok / second_fix_den * 100.0), 2) if second_fix_den else 0.0,
                    "second_attempt_fix_cases": {"fixed": second_fix_ok, "total": second_fix_den},
                    "error_severity": {"conceptual": sev_con, "sintaxis": sev_syn},
                },
                "ml": {
                    "risk_prob": round(float(pred.get("risk_prob") or 0.0), 3),
                    "risk_level": pred.get("risk_level", "bajo"),
                    "model": pred.get("model", "heuristic"),
                },
                "responses_count": total_responses,
            }
        )

    @app.get("/api/teacher/session/<token>/summary")
    def teacher_session_summary(token: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            summary = session_summary(conn, token, include_correct_answer=True, mark_viewed=False)
            if not summary:
                return jsonify({"error": "Sesion no encontrada"}), 404
            if summary.get("error"):
                return jsonify({"error": summary["error"]}), 400

            row = conn.execute(
                "SELECT student_name, student_email FROM exam_sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
            if not row:
                return jsonify({"error": "Sesion no encontrada"}), 404
            target_key = student_key_for_cycle(row["student_name"], row["student_email"])
            sessions_all = conn.execute(
                "SELECT session_token, student_name, student_email, score, total_items, started_at, finished_at, completed FROM exam_sessions"
            ).fetchall()
            related = [dict(s) for s in sessions_all if student_key_for_cycle(s["student_name"], s["student_email"]) == target_key and int(s["completed"] or 0) == 1]

        score_pcts = [
            (int(s.get("score") or 0) / max(1, int(s.get("total_items") or 0))) * 100.0
            for s in related
        ]
        elapsed_vals = [elapsed_seconds(s.get("started_at"), s.get("finished_at")) for s in related]
        current_pct = (float(summary["score"]) / max(1, int(summary["total"]))) * 100.0
        comparative = {
            "student_attempts_completed": len(related),
            "current_score_pct": round(current_pct, 2),
            "student_avg_score_pct": round(float(statistics.mean(score_pcts)) if score_pcts else 0.0, 2),
            "current_elapsed_seconds": int(summary["elapsed_seconds"]),
            "student_avg_elapsed_seconds": int(statistics.mean(elapsed_vals)) if elapsed_vals else 0,
            }
        return jsonify({"summary": summary, "comparative": comparative})

    @app.post("/api/teacher/session/<token>/question/<int:question_number>/grade")
    def teacher_override_question_grade(token: str, question_number: int):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        req = request.get_json(force=True, silent=True) or {}
        is_correct_raw = req.get("is_correct")
        if isinstance(is_correct_raw, bool):
            is_correct = is_correct_raw
        elif str(is_correct_raw).strip() in {"1", "true", "True", "si", "yes"}:
            is_correct = True
        elif str(is_correct_raw).strip() in {"0", "false", "False", "no"}:
            is_correct = False
        else:
            return jsonify({"error": "is_correct invalido"}), 400

        with get_db() as conn:
            session_row = conn.execute(
                "SELECT total_items FROM exam_sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
            if not session_row:
                return jsonify({"error": "Sesion no encontrada"}), 404
            total_items = int(session_row["total_items"] or 0)
            if question_number < 1 or question_number > total_items:
                return jsonify({"error": "Numero de pregunta invalido"}), 400
            idx = question_number - 1
            response_row = conn.execute(
                "SELECT id FROM responses WHERE session_token = ? AND item_index = ?",
                (token, idx),
            ).fetchone()
            if not response_row:
                return jsonify({"error": "No hay respuesta registrada para esta pregunta"}), 404

            conn.execute(
                """
                UPDATE responses
                SET is_correct = ?, submitted_at = ?
                WHERE session_token = ? AND item_index = ?
                """,
                (1 if is_correct else 0, utcnow_iso(), token, idx),
            )
            new_score = recalculate_score(conn, token)
            conn.execute(
                "UPDATE exam_sessions SET score = ? WHERE session_token = ?",
                (new_score, token),
            )
        return jsonify(
            {
                "ok": True,
                "question_number": question_number,
                "is_correct": bool(is_correct),
                "new_score": int(new_score),
            }
        )

    @app.get("/api/teacher/session/<token>/summary.csv")
    def teacher_session_summary_csv(token: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            summary = session_summary(conn, token, include_correct_answer=True, mark_viewed=False)
            if not summary:
                return jsonify({"error": "Sesion no encontrada"}), 404
            if summary.get("error"):
                return jsonify({"error": summary["error"]}), 400

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["session_token", "student_name", "student_email", "score", "total", "elapsed_seconds"])
        writer.writerow(
            [
                summary["session_token"],
                summary["student_name"],
                summary["student_email"],
                summary["score"],
                summary["total"],
                summary["elapsed_seconds"],
            ]
        )
        writer.writerow([])
        writer.writerow(["question_number", "item_id", "topic", "status", "your_answer", "correct_answer", "seconds_spent", "prompt"])
        for q in summary["questions"]:
            writer.writerow(
                [
                    q["question_number"],
                    q["item_id"],
                    q["topic"],
                    q["status"],
                    q["your_answer"],
                    q["correct_answer"],
                    q["seconds_spent"],
                    q["prompt"],
                ]
            )
        content = buf.getvalue()
        return Response(
            content,
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename=session_{token}_summary.csv"},
        )

    @app.get("/api/teacher/session/<token>/summary.pdf")
    def teacher_session_summary_pdf(token: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            summary = session_summary(conn, token, include_correct_answer=True, mark_viewed=False)
            if not summary:
                return jsonify({"error": "Sesion no encontrada"}), 404
            if summary.get("error"):
                return jsonify({"error": summary["error"]}), 400

        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas
            from reportlab.pdfbase import pdfdoc
        except Exception:
            return jsonify({"error": "PDF no disponible: falta reportlab en servidor"}), 500

        import hashlib

        original_md5 = hashlib.md5

        def md5_compat(*args, **kwargs):
            kwargs.pop("usedforsecurity", None)
            return original_md5(*args, **kwargs)

        pdfdoc.md5 = md5_compat
        pdf_buf = io.BytesIO()
        c = canvas.Canvas(pdf_buf, pagesize=A4)
        width, height = A4
        y = height - 36
        c.setFont("Helvetica-Bold", 13)
        c.drawString(36, y, f"Resumen de intento - {summary['student_name']} ({summary['student_email']})")
        y -= 20
        c.setFont("Helvetica", 10)
        c.drawString(36, y, f"Sesion: {summary['session_token']}")
        y -= 14
        c.drawString(36, y, f"Puntaje: {summary['score']}/{summary['total']}  |  Tiempo: {summary['elapsed_seconds']}s")
        y -= 18
        c.setFont("Helvetica-Bold", 9)
        c.drawString(36, y, "#")
        c.drawString(58, y, "Estado")
        c.drawString(116, y, "Tema")
        c.drawString(260, y, "Tu respuesta")
        c.drawString(410, y, "Correcta")
        y -= 12
        c.setFont("Helvetica", 8)
        for q in summary["questions"]:
            if y < 48:
                c.showPage()
                y = height - 36
                c.setFont("Helvetica", 8)
            c.drawString(36, y, str(q["question_number"]))
            c.drawString(58, y, str(q["status"])[:10])
            c.drawString(116, y, str(q["topic"])[:28])
            c.drawString(260, y, str(q["your_answer"])[:30])
            c.drawString(410, y, str(q["correct_answer"])[:30])
            y -= 11
        c.save()
        return Response(
            pdf_buf.getvalue(),
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=session_{token}_summary.pdf"},
        )

    @app.get("/api/teacher/live")
    def teacher_live():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            sessions = conn.execute(
                """
                SELECT
                    s.session_token,
                    s.student_name,
                    s.student_email,
                    s.started_at,
                    s.finished_at,
                    s.current_index,
                    s.total_items,
                    s.completed,
                    s.score,
                    s.resets_count,
                    s.exam_level,
                    s.exam_payload,
                    COALESCE(a.archive_count, 0) AS archive_count
                FROM exam_sessions s
                LEFT JOIN (
                    SELECT session_token, COUNT(*) AS archive_count
                    FROM exam_archives
                    GROUP BY session_token
                ) a ON a.session_token = s.session_token
                ORDER BY started_at DESC
                """
            ).fetchall()

            responses_latest = conn.execute(
                """
                SELECT r.session_token, s.student_name, s.student_email, r.item_index, r.item_id, r.item_type, r.prompt, r.user_answer, r.distro_guess, r.command_trace, r.extra_text, r.is_correct, r.expected, r.submitted_at
                FROM responses r
                JOIN exam_sessions s ON s.session_token = r.session_token
                ORDER BY r.submitted_at DESC
                LIMIT 100
                """
            ).fetchall()

            responses_all = conn.execute(
                """
                SELECT r.session_token, s.student_name, s.student_email, r.item_index, r.item_id, r.item_type, r.prompt, r.user_answer, r.distro_guess, r.command_trace, r.extra_text, r.is_correct, r.expected, r.submitted_at
                FROM responses r
                JOIN exam_sessions s ON s.session_token = r.session_token
                ORDER BY r.submitted_at DESC
                """
            ).fetchall()

            timings = conn.execute(
                """
                SELECT t.session_token, s.student_name, t.item_index, t.seconds_spent, t.last_entered_at
                FROM question_timing t
                JOIN exam_sessions s ON s.session_token = t.session_token
                ORDER BY s.started_at DESC, t.item_index ASC
                """
            ).fetchall()

            attempts = conn.execute(
                """
                SELECT session_token, item_index, attempt_no, is_correct
                FROM response_attempts
                ORDER BY session_token, item_index, attempt_no
                """
            ).fetchall()

            level_rows = conn.execute(
                "SELECT student_email, exam_level FROM student_levels"
            ).fetchall()

        now_iso = utcnow_iso()
        level_by_email = {normalize_email(r["student_email"]): int(r["exam_level"] or 1) for r in level_rows}
        session_data = []
        for s in sessions:
            d = dict(s)
            email_key = normalize_email(d.get("student_email") or "")
            d["assigned_level"] = int(level_by_email.get(email_key, int(d.get("exam_level") or 1)))
            d["elapsed_seconds"] = elapsed_seconds(d["started_at"], d["finished_at"])
            d["is_archived"] = int(d.get("archive_count") or 0) > 0
            try:
                payload = json.loads(d.get("exam_payload") or "[]")
            except Exception:
                payload = []
            idx = int(d.get("current_index") or 0)
            if d.get("completed"):
                d["current_question_number"] = int(d.get("total_items") or 0)
                d["current_question_prompt"] = "Examen finalizado"
            elif payload and 0 <= idx < len(payload):
                prompt = (payload[idx].get("prompt") or "").strip()
                if len(prompt) > 95:
                    prompt = prompt[:95].rstrip() + "..."
                d["current_question_number"] = idx + 1
                d["current_question_prompt"] = prompt
            else:
                d["current_question_number"] = idx + 1
                d["current_question_prompt"] = "-"
            d.pop("exam_payload", None)
            session_data.append(d)

        timing_map: Dict[Tuple[str, int], int] = {}
        timing_data = []
        for t in timings:
            d = dict(t)
            extra = elapsed_seconds(d["last_entered_at"], now_iso) if d.get("last_entered_at") else 0
            d["seconds_total"] = int(float(d["seconds_spent"]) + extra)
             # key por sesion/pregunta para KPIs
            timing_map[(d["session_token"], int(d["item_index"]))] = d["seconds_total"]
            timing_data.append(d)

        response_data = []
        for r in responses_latest:
            d = dict(r)
            idx = int(d.get("item_index") or 0)
            if DISTRO_ROTATION:
                expected = DISTRO_ROTATION[idx % len(DISTRO_ROTATION)]
                d["distro_expected_name"] = expected["name"]
                d["distro_image_name"] = expected["image"]
                d["distro_image_url"] = f"/CursoLinux/static/images/distros/{expected['image']}"
                guess_norm = normalize_key(d.get("distro_guess") or "")
                expected_norm = normalize_key(expected["name"])
                d["distro_guess_match"] = bool(
                    guess_norm
                    and expected_norm
                    and (guess_norm == expected_norm or guess_norm in expected_norm or expected_norm in guess_norm)
                )
            else:
                d["distro_expected_name"] = ""
                d["distro_image_name"] = ""
                d["distro_image_url"] = ""
                d["distro_guess_match"] = False
            d["topic"] = topic_for_item_id(d.get("item_id", ""))
            trace_list = []
            trace_raw = d.get("command_trace")
            if isinstance(trace_raw, str) and trace_raw:
                try:
                    parsed = json.loads(trace_raw)
                    if isinstance(parsed, list):
                        trace_list = [str(x) for x in parsed]
                except Exception:
                    trace_list = []
            d["error_severity"] = classify_error_severity(
                d.get("item_type", ""),
                d.get("item_id", ""),
                d.get("user_answer", ""),
                d.get("expected", ""),
                trace_list,
            ) if not d.get("is_correct") else "none"
            response_data.append(d)

        topic_stats: Dict[str, Dict] = defaultdict(lambda: {"total": 0, "correct": 0, "times": [], "syntax": 0, "conceptual": 0})
        student_stats: Dict[str, Dict] = defaultdict(
            lambda: {
                "student_name": "",
                "student_email": "",
                "total": 0,
                "correct": 0,
                "times": [],
                "resets": 0,
                "dropouts": 0,
                "syntax_err": 0,
                "conceptual_err": 0,
                "topic": defaultdict(lambda: {"total": 0, "correct": 0}),
            }
        )

        for s in session_data:
            skey = student_key_for_cycle(s.get("student_name", ""), s.get("student_email", ""))
            st = student_stats[skey]
            st["student_name"] = s.get("student_name", "")
            st["student_email"] = s.get("student_email", "")
            st["resets"] += int(s.get("resets_count") or 0)
            # abandono: sesiones no completadas con >10 min transcurridos
            if not s.get("completed") and int(s.get("elapsed_seconds") or 0) >= 600:
                st["dropouts"] += 1

        for r in responses_all:
            d = dict(r)
            item_id = d.get("item_id", "")
            topic = topic_for_item_id(item_id)
            sess = d.get("session_token", "")
            qidx = int(d.get("item_index") or 0)
            is_correct = int(d.get("is_correct") or 0) == 1
            topic_stats[topic]["total"] += 1
            topic_stats[topic]["correct"] += 1 if is_correct else 0
            sec = timing_map.get((sess, qidx))
            if sec is not None:
                topic_stats[topic]["times"].append(sec)
            trace_list = []
            trace_raw = d.get("command_trace")
            if isinstance(trace_raw, str) and trace_raw:
                try:
                    parsed = json.loads(trace_raw)
                    if isinstance(parsed, list):
                        trace_list = [str(x) for x in parsed]
                except Exception:
                    trace_list = []
            sev = classify_error_severity(
                d.get("item_type", ""),
                item_id,
                d.get("user_answer", ""),
                d.get("expected", ""),
                trace_list,
            ) if not is_correct else "none"
            if sev == "sintaxis":
                topic_stats[topic]["syntax"] += 1
            elif sev == "conceptual":
                topic_stats[topic]["conceptual"] += 1

            skey = student_key_for_cycle(d.get("student_name", ""), d.get("student_email", ""))
            st = student_stats[skey]
            st["student_name"] = d.get("student_name", "")
            st["student_email"] = d.get("student_email", "")
            st["total"] += 1
            st["correct"] += 1 if is_correct else 0
            if sec is not None:
                st["times"].append(sec)
            st["topic"][topic]["total"] += 1
            st["topic"][topic]["correct"] += 1 if is_correct else 0
            if sev == "sintaxis":
                st["syntax_err"] += 1
            elif sev == "conceptual":
                st["conceptual_err"] += 1

        attempt_groups: Dict[Tuple[str, int], List[Dict]] = defaultdict(list)
        for a in attempts:
            dd = dict(a)
            attempt_groups[(dd["session_token"], int(dd["item_index"]))].append(dd)
        second_fix_den = 0
        second_fix_ok = 0
        for _, group in attempt_groups.items():
            group = sorted(group, key=lambda x: int(x.get("attempt_no") or 0))
            if len(group) < 2:
                continue
            first_bad = int(group[0].get("is_correct") or 0) == 0
            second_good = int(group[1].get("is_correct") or 0) == 1
            if first_bad:
                second_fix_den += 1
                if second_good:
                    second_fix_ok += 1

        topic_precision = []
        topic_median_time = []
        severity_conceptual = 0
        severity_syntax = 0
        for topic, st in topic_stats.items():
            total = int(st["total"] or 0)
            correct = int(st["correct"] or 0)
            acc = (correct / total * 100.0) if total else 0.0
            topic_precision.append({"topic": topic, "precision_pct": round(acc, 2), "total": total})
            med_t = int(statistics.median(st["times"])) if st["times"] else 0
            topic_median_time.append({"topic": topic, "median_seconds": med_t})
            severity_conceptual += int(st["conceptual"] or 0)
            severity_syntax += int(st["syntax"] or 0)

        topic_precision.sort(key=lambda x: (x["precision_pct"], -x["total"]))
        topic_median_time.sort(key=lambda x: x["median_seconds"], reverse=True)

        # Progreso acumulado por alumno (mejora entre primer y ultimo intento completado)
        attempts_by_student: Dict[str, List[Dict]] = defaultdict(list)
        for s in session_data:
            skey = student_key_for_cycle(s.get("student_name", ""), s.get("student_email", ""))
            attempts_by_student[skey].append(s)
        student_progress = []
        for skey, rows in attempts_by_student.items():
            rows_sorted = sorted(rows, key=lambda x: x.get("started_at") or "")
            completed_rows = [x for x in rows_sorted if x.get("completed")]
            first_pct = 0.0
            last_pct = 0.0
            improvement = 0.0
            if completed_rows:
                first = completed_rows[0]
                last = completed_rows[-1]
                first_total = max(1, int(first.get("total_items") or 0))
                last_total = max(1, int(last.get("total_items") or 0))
                first_pct = float(first.get("score") or 0) / first_total * 100.0
                last_pct = float(last.get("score") or 0) / last_total * 100.0
                improvement = last_pct - first_pct
            st = student_stats.get(skey) or {}
            weak_topic = ""
            weak_pct = 100.0
            for topic, tstat in (st.get("topic") or {}).items():
                t_total = int(tstat.get("total") or 0)
                if t_total <= 0:
                    continue
                t_pct = float(tstat.get("correct") or 0) / t_total * 100.0
                if t_pct < weak_pct:
                    weak_pct = t_pct
                    weak_topic = topic
            student_progress.append(
                {
                    "student_key": skey,
                    "student_name": rows_sorted[-1].get("student_name", "") if rows_sorted else "",
                    "student_email": rows_sorted[-1].get("student_email", "") if rows_sorted else "",
                    "attempts_total": len(rows_sorted),
                    "attempts_completed": len(completed_rows),
                    "latest_score_pct": round(last_pct, 2),
                    "first_score_pct": round(first_pct, 2),
                    "improvement_pct": round(improvement, 2),
                    "weakest_topic": weak_topic or DEFAULT_TOPIC,
                    "weakest_topic_precision_pct": round(weak_pct if weak_topic else 0.0, 2),
                }
            )

        student_feature_rows = []
        for sp in student_progress:
            skey = sp["student_key"]
            st = student_stats.get(skey) or {}
            total = int(st.get("total") or 0)
            correct = int(st.get("correct") or 0)
            wrong_rate = (1.0 - (correct / total)) if total else 1.0
            median_time_topic = float(statistics.median(st.get("times") or [0])) if (st.get("times") or []) else 0.0
            syntax_err = int(st.get("syntax_err") or 0)
            conceptual_err = int(st.get("conceptual_err") or 0)
            err_total = max(1, syntax_err + conceptual_err)
            syntax_ratio = float(syntax_err) / float(err_total)
            student_feature_rows.append(
                {
                    "student_key": skey,
                    "wrong_rate": wrong_rate,
                    "median_time_topic": median_time_topic,
                    "resets": int(st.get("resets") or 0),
                    "dropouts": int(st.get("dropouts") or 0),
                    "syntax_error_ratio": syntax_ratio,
                }
            )

        ml_risk = build_ml_risk(student_feature_rows)
        for sp in student_progress:
            pred = ml_risk.get(sp["student_key"], {"risk_prob": 0.0, "risk_level": "bajo", "model": "heuristic"})
            sp["risk_prob"] = round(float(pred.get("risk_prob") or 0.0), 3)
            sp["risk_level"] = pred.get("risk_level", "bajo")
            sp["risk_model"] = pred.get("model", "heuristic")

        student_progress.sort(key=lambda x: (-x["risk_prob"], x["latest_score_pct"]))

        kpis = {
            "precision_by_topic": topic_precision,
            "median_time_by_topic": topic_median_time,
            "second_attempt_fix_rate_pct": round((second_fix_ok / second_fix_den * 100.0), 2) if second_fix_den else 0.0,
            "second_attempt_fix_cases": {"fixed": second_fix_ok, "total": second_fix_den},
            "restarts_total": int(sum(int(s.get("resets_count") or 0) for s in session_data)),
            "dropouts_total": int(sum(1 for s in session_data if (not s.get("completed")) and int(s.get("elapsed_seconds") or 0) >= 600)),
            "error_severity": {"conceptual": severity_conceptual, "sintaxis": severity_syntax},
            "students_needing_support": [x for x in student_progress if x.get("risk_level") in {"alto", "medio"}][:20],
        }

        return jsonify(
            {
                "sessions": session_data,
                "responses": response_data,
                "distros": [x for x in response_data if (x.get("distro_guess") or "").strip()],
                "timings": timing_data,
                "kpis": kpis,
                "student_progress": student_progress,
                "ml_risk": student_progress[:20],
                "server_time": utcnow_iso(),
            }
        )

    @app.post("/api/teacher/reset/<token>")
    def teacher_reset_exam(token: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            row = conn.execute(
                "SELECT session_token FROM exam_sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
            if not row:
                return jsonify({"error": "Sesion no encontrada"}), 404

            session_meta = conn.execute(
                "SELECT student_name, student_email, current_index, exam_level FROM exam_sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
            student_key = student_key_for_cycle(session_meta["student_name"], session_meta["student_email"]) if session_meta else ""
            fallback_level = int(session_meta["exam_level"] or 1) if session_meta else 1
            assigned_level = get_student_level(
                conn,
                session_meta["student_email"] if session_meta else "",
                default_level=fallback_level,
            )
            new_items = build_exam(student_key=student_key, conn=conn, exam_level=assigned_level)
            current_idx = int(session_meta["current_index"]) if session_meta else 0
            leave_question(conn, token, current_idx)
            conn.execute("DELETE FROM responses WHERE session_token = ?", (token,))
            conn.execute("DELETE FROM question_timing WHERE session_token = ?", (token,))
            conn.execute(
                """
                UPDATE exam_sessions
                SET started_at = ?,
                    finished_at = NULL,
                    current_index = 0,
                    max_reached_index = 0,
                    total_items = ?,
                    completed = 0,
                    score = 0,
                    resets_count = resets_count + 1,
                    exam_level = ?,
                    exam_payload = ?
                WHERE session_token = ?
                """,
                (utcnow_iso(), len(new_items), int(assigned_level), json.dumps(new_items), token),
            )
            enter_question(conn, token, 0)

        return jsonify({"ok": True, "message": "Examen reiniciado"})

    @app.post("/api/teacher/delete/<token>")
    def teacher_delete_exam(token: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        req = request.get_json(force=True, silent=True) or {}
        protected_password = (req.get("protected_password") or "").strip()
        with get_db() as conn:
            row = conn.execute(
                "SELECT session_token FROM exam_sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
            if not row:
                return jsonify({"error": "Sesion no encontrada"}), 404
            archived = conn.execute(
                "SELECT COUNT(*) AS c FROM exam_archives WHERE session_token = ?",
                (token,),
            ).fetchone()
            if archived and int(archived["c"]) > 0:
                if not compare_digest(protected_password, PROTECTED_DELETE_PASSWORD):
                    return jsonify({"error": "Password invalido para borrar examen protegido"}), 403

            conn.execute("DELETE FROM responses WHERE session_token = ?", (token,))
            conn.execute("DELETE FROM question_timing WHERE session_token = ?", (token,))
            conn.execute("DELETE FROM exam_sessions WHERE session_token = ?", (token,))
            if archived and int(archived["c"]) > 0:
                conn.execute("DELETE FROM exam_archives WHERE session_token = ?", (token,))

        return jsonify({"ok": True, "message": "Examen eliminado"})

    @app.post("/api/teacher/save/<token>")
    def teacher_save_exam(token: str):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error

        with get_db() as conn:
            session_row = conn.execute(
                "SELECT * FROM exam_sessions WHERE session_token = ?",
                (token,),
            ).fetchone()
            if not session_row:
                return jsonify({"error": "Sesion no encontrada"}), 404

            responses = conn.execute(
                """
                SELECT *
                FROM responses
                WHERE session_token = ?
                ORDER BY item_index ASC, submitted_at ASC
                """,
                (token,),
            ).fetchall()

            timings = conn.execute(
                """
                SELECT *
                FROM question_timing
                WHERE session_token = ?
                ORDER BY item_index ASC
                """,
                (token,),
            ).fetchall()

            session_dict = dict(session_row)
            try:
                questions = json.loads(session_dict.get("exam_payload") or "[]")
            except Exception:
                questions = []

            now_iso = utcnow_iso()
            timing_data = []
            for t in timings:
                d = dict(t)
                extra = elapsed_seconds(d["last_entered_at"], now_iso) if d.get("last_entered_at") else 0
                d["seconds_total"] = int(float(d.get("seconds_spent", 0)) + extra)
                timing_data.append(d)

            snapshot = {
                "exported_at": now_iso,
                "session": session_dict,
                "questions": questions,
                "responses": [dict(r) for r in responses],
                "timings": timing_data,
                "metrics": {
                    "answered_count": len(responses),
                    "total_items": int(session_dict.get("total_items") or 0),
                    "score": int(session_dict.get("score") or 0),
                    "completed": bool(session_dict.get("completed")),
                    "elapsed_seconds": elapsed_seconds(session_dict.get("started_at"), session_dict.get("finished_at")),
                },
            }

            cur = conn.execute(
                """
                INSERT INTO exam_archives (session_token, saved_at, saved_by, snapshot_json)
                VALUES (?, ?, ?, ?)
                """,
                (token, now_iso, app.config["TEACHER_USER"], json.dumps(snapshot, ensure_ascii=False)),
            )

        return jsonify(
            {
                "ok": True,
                "archive_id": int(cur.lastrowid),
                "saved_at": now_iso,
                "message": "Examen guardado en base de datos",
            }
        )

    @app.get("/teacher/history")
    def teacher_history_page():
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT id, session_token, saved_at, saved_by, snapshot_json
                FROM exam_archives
                ORDER BY saved_at DESC, id DESC
                LIMIT 300
                """
            ).fetchall()

        archives = []
        for r in rows:
            d = dict(r)
            try:
                snap = json.loads(d.get("snapshot_json") or "{}")
            except Exception:
                snap = {}
            sess = snap.get("session") or {}
            metrics = snap.get("metrics") or {}
            archives.append(
                {
                    "id": d["id"],
                    "session_token": d["session_token"],
                    "saved_at": d["saved_at"],
                    "saved_by": d["saved_by"],
                    "student_name": sess.get("student_name", "-"),
                    "student_email": sess.get("student_email", "-"),
                    "score": int(metrics.get("score") or 0),
                    "total_items": int(metrics.get("total_items") or 0),
                    "elapsed_seconds": int(metrics.get("elapsed_seconds") or 0),
                    "completed": bool(metrics.get("completed")),
                }
            )
        return render_template("teacher_history.html", archives=archives, show_teacher_link=True, teacher_nav_mode=True)

    @app.get("/teacher/history/<int:archive_id>")
    def teacher_history_detail_page(archive_id: int):
        auth_error = require_teacher_auth()
        if auth_error:
            return auth_error
        with get_db() as conn:
            row = conn.execute(
                """
                SELECT id, session_token, saved_at, saved_by, snapshot_json
                FROM exam_archives
                WHERE id = ?
                """,
                (archive_id,),
            ).fetchone()
        if not row:
            return redirect(url_for("teacher_history_page"))

        d = dict(row)
        try:
            snap = json.loads(d.get("snapshot_json") or "{}")
        except Exception:
            snap = {}
        session_info = snap.get("session") or {}
        responses = snap.get("responses") or []
        timings = snap.get("timings") or []
        questions = snap.get("questions") or []
        metrics = snap.get("metrics") or {}

        for r in responses:
            trace = r.get("command_trace")
            if isinstance(trace, str) and trace:
                try:
                    parsed = json.loads(trace)
                    if isinstance(parsed, list):
                        r["command_trace_list"] = [str(x) for x in parsed]
                    else:
                        r["command_trace_list"] = []
                except Exception:
                    r["command_trace_list"] = []
            elif isinstance(trace, list):
                r["command_trace_list"] = [str(x) for x in trace]
            else:
                r["command_trace_list"] = []

        timing_points = []
        for t in timings:
            item_idx = int(t.get("item_index") or 0)
            timing_points.append(
                {
                    "question_number": item_idx + 1,
                    "seconds_total": int(t.get("seconds_total") or t.get("seconds_spent") or 0),
                }
            )
        timing_points.sort(key=lambda x: x["question_number"])

        return render_template(
            "teacher_history_detail.html",
            archive_id=archive_id,
            archive_saved_at=d["saved_at"],
            archive_saved_by=d["saved_by"],
            session_info=session_info,
            metrics=metrics,
            responses=responses,
            timings=timing_points,
            questions=questions,
            show_teacher_link=True,
            teacher_nav_mode=True,
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
