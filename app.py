import csv
import io
import copy
import json
import os
import random
import re
import sqlite3
import time
import unicodedata
import uuid
from hmac import compare_digest
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

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
]

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
        "type": "mcq",
        "prompt": "Selecciona el comando COMPLETO para cambiar la contrasena del usuario operador.",
        "choices": ["passwd operador", "useradd -p operador", "usermod -p operador", "chpasswd operador"],
        "correct": 0,
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
        "id": "img_top_issue",
        "type": "image_click",
        "prompt": "Observa la captura de top y haz click en el proceso que indica el problema principal.",
        "image_url": "/CursoLinux/static/images/top_snapshot.png",
        "hotspots": [
            {"id": "cpu", "x": 3, "y": 17, "w": 92, "h": 9},
            {"id": "swap", "x": 3, "y": 42, "w": 92, "h": 9},
            {"id": "zombie", "x": 3, "y": 30, "w": 92, "h": 9},
            {"id": "proc", "x": 3, "y": 58, "w": 92, "h": 14},
        ],
        "correct": "swap",
        "expected": "swap (uso alto de swap)",
    },
    {
        "id": "img_htop_issue",
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
        ],
        "expected": "find /home/alumno -type d -name respaldo",
        "success_output": "/home/alumno/lab/respaldo",
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
        "title": "Hashes en /etc/shadow",
        "prompt": "Muestra el archivo /etc/shadow para identificar hashes.",
        "terminal_hint": "alumno@linux:~$",
        "accepted": [
            r"^cat\s+/etc/shadow$",
            r"^sudo\s+cat\s+/etc/shadow$",
            r"^cat\s+shadow$",
            r"^sudo\s+cat\s+shadow$",
            r"^more\s+/etc/shadow$",
            r"^sudo\s+more\s+/etc/shadow$",
            r"^more\s+shadow$",
            r"^sudo\s+more\s+shadow$",
        ],
        "expected": "cat /etc/shadow",
        "success_output": "Archivo /etc/shadow mostrado con hashes.",
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
        response_cols = conn.execute("PRAGMA table_info(responses)").fetchall()
        response_names = {c["name"] for c in response_cols}
        if "distro_guess" not in response_names:
            conn.execute("ALTER TABLE responses ADD COLUMN distro_guess TEXT NOT NULL DEFAULT ''")
        if "command_trace" not in response_names:
            conn.execute("ALTER TABLE responses ADD COLUMN command_trace TEXT NOT NULL DEFAULT ''")
        if "extra_text" not in response_names:
            conn.execute("ALTER TABLE responses ADD COLUMN extra_text TEXT NOT NULL DEFAULT ''")


def build_exam() -> List[Dict]:
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

    command = []
    if cups_cmd:
        command.append(random.choice(cups_cmd))
    if fw_cmd:
        command.append(random.choice(fw_cmd))
    if chmod_num_cmd:
        command.append(random.choice(chmod_num_cmd))
    if pkg_cmd:
        command.append(random.choice(pkg_cmd))
    remaining_cmd = max(0, min(12, len(COMMAND_QUESTIONS)) - len(command))
    pool_cmd = [q for q in other_cmd if q not in command]
    if pool_cmd and remaining_cmd > 0:
        command.extend(random.sample(pool_cmd, k=min(remaining_cmd, len(pool_cmd))))

    history = []
    if kernel_hist:
        history.append(random.choice(kernel_hist))
    remaining_hist = max(0, min(3, len(HISTORY_QUESTIONS)) - len(history))
    pool_hist = [q for q in other_hist if q not in history]
    if pool_hist and remaining_hist > 0:
        history.extend(random.sample(pool_hist, k=min(remaining_hist, len(pool_hist))))

    session3 = random.sample(SESSION3_IMAGE_QUESTIONS, k=min(4, len(SESSION3_IMAGE_QUESTIONS)))
    images = random.sample(IMAGE_QUESTIONS, k=min(2, len(IMAGE_QUESTIONS)))
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
        shell.append(random.choice(cat_shell))
    if df_shell:
        shell.append(random.choice(df_shell))
    if mv_shell:
        shell.append(random.choice(mv_shell))
    remaining_shell = max(0, min(8, len(SHELL_EXERCISES)) - len(shell))
    blocked_shell_ids = {"shell_shadow_hashes"} if cat_shell else set()
    pool_shell = [q for q in other_shell if q not in shell and q["id"] not in blocked_shell_ids]
    if pool_shell and remaining_shell > 0:
        shell.extend(random.sample(pool_shell, k=min(remaining_shell, len(pool_shell))))
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


def create_app() -> Flask:
    app = Flask(__name__, instance_path=str(INSTANCE_DIR))
    app.config["SECRET_KEY"] = os.environ.get("CURSO_LINUX_SECRET", "curso-linux-dev-key")
    app.config["TEACHER_USER"] = os.environ.get("CURSO_LINUX_TEACHER_USER", "teacher")
    app.config["TEACHER_PASSWORD"] = os.environ.get("CURSO_LINUX_TEACHER_PASSWORD", "ikusi2026")
    init_db()

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
        student_email = request.form.get("student_email", "").strip().lower()
        if not student_name:
            return render_template("student_select.html", error="Ingresa tu nombre completo", show_teacher_link=False)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", student_email):
            return render_template("student_select.html", error="Ingresa un correo valido", show_teacher_link=False)

        with get_db() as conn:
            existing = conn.execute(
                """
                SELECT session_token
                FROM exam_sessions
                WHERE student_name = ? AND student_email = ? AND completed = 0
                ORDER BY started_at DESC
                LIMIT 1
                """,
                (student_name, student_email),
            ).fetchone()
            if existing:
                return redirect(url_for("exam_page", token=existing["session_token"]))

            token = str(uuid.uuid4())
            items = build_exam()
            conn.execute(
                """
                INSERT INTO exam_sessions
                (session_token, student_name, student_email, started_at, total_items, exam_payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token, student_name, student_email, utcnow_iso(), len(items), json.dumps(items)),
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
                return jsonify(
                    {
                        "completed": True,
                        "score": row["score"],
                        "total": row["total_items"],
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
        return render_template("teacher.html", show_teacher_link=True)

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
                    s.started_at,
                    s.finished_at,
                    s.current_index,
                    s.total_items,
                    s.completed,
                    s.score,
                    s.resets_count,
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

            responses = conn.execute(
                """
                SELECT r.session_token, s.student_name, r.item_index, r.item_type, r.prompt, r.user_answer, r.distro_guess, r.command_trace, r.extra_text, r.is_correct, r.submitted_at
                FROM responses r
                JOIN exam_sessions s ON s.session_token = r.session_token
                ORDER BY r.submitted_at DESC
                LIMIT 100
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

        now_iso = utcnow_iso()
        session_data = []
        for s in sessions:
            d = dict(s)
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

        timing_data = []
        for t in timings:
            d = dict(t)
            extra = elapsed_seconds(d["last_entered_at"], now_iso) if d.get("last_entered_at") else 0
            d["seconds_total"] = int(float(d["seconds_spent"]) + extra)
            timing_data.append(d)

        response_data = []
        for r in responses:
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
            response_data.append(d)

        return jsonify(
            {
                "sessions": session_data,
                "responses": response_data,
                "distros": [x for x in response_data if (x.get("distro_guess") or "").strip()],
                "timings": timing_data,
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

            new_items = build_exam()
            current_idx = int(conn.execute("SELECT current_index FROM exam_sessions WHERE session_token = ?", (token,)).fetchone()["current_index"])
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
                    exam_payload = ?
                WHERE session_token = ?
                """,
                (utcnow_iso(), len(new_items), json.dumps(new_items), token),
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
        return render_template("teacher_history.html", archives=archives, show_teacher_link=True)

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
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
