# CursoLinux - Aula + Examen Linux en vivo

MVP en Python/Flask para:
- Seleccion de alumno.
- Examen mixto (preguntas y ejercicios tipo shell).
- Calificacion automatica por reactivo.
- Dashboard del profesor con monitoreo en tiempo real (polling cada 2 segundos).

## Estructura
- `app.py`: API, logica de examen, banco de preguntas, persistencia SQLite.
- `templates/`: vistas de alumno/examen/profesor.
- `static/style.css`: estilos.
- `instance/curso_linux.db`: base de datos (se crea sola).
- `wsgi.py`: entrada para Apache mod_wsgi.

## Ejecucion local
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Abrir:
- Alumno: `http://127.0.0.1:5000/`
- Profesor: `http://127.0.0.1:5000/teacher`

## Deploy en Apache (servidor `androidtv.com.mx`)
Ruta objetivo: `/var/www/html/CursoLinux`

1. Copiar carpeta del proyecto.
2. Crear entorno virtual en servidor e instalar dependencias.
3. Configurar VirtualHost o Alias con `mod_wsgi`.

Ejemplo de bloque Apache:
```apache
WSGIDaemonProcess CursoLinux python-home=/var/www/html/CursoLinux/.venv python-path=/var/www/html/CursoLinux
WSGIProcessGroup CursoLinux
WSGIScriptAlias /CursoLinux /var/www/html/CursoLinux/wsgi.py

<Directory /var/www/html/CursoLinux>
    Require all granted
</Directory>

Alias /CursoLinux/static /var/www/html/CursoLinux/static
<Directory /var/www/html/CursoLinux/static>
    Require all granted
</Directory>
```

Reiniciar Apache:
```bash
sudo systemctl restart apache2
```

## Notas
- El banco de reactivos es variable por alumno (aleatorio por sesion).
- Los ejercicios shell son evaluados por patrones de comando aceptados.
- Si quieres autenticacion de profesor y exportacion a Excel/PDF, se puede agregar en la siguiente iteracion.
