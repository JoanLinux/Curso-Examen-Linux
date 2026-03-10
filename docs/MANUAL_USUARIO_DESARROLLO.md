# Manual de Usuario (Desarrollo) - CursoLinux

## 1) Objetivo
Guía rápida para operar, probar y mantener la plataforma de clase/evaluación Linux en ambiente de desarrollo y UAT.

## 2) Requisitos
- Python 3.10+ (local; en UAT puede variar)
- Dependencias del proyecto:
  - `Flask`
  - `requests`
- Base de datos SQLite:
  - `instance/curso_linux.db`

## 3) Estructura principal
- `app.py`: lógica de examen, APIs, evaluación y dashboard.
- `templates/`: vistas (`cover`, `exam`, `teacher`, etc.).
- `static/style.css`: estilos.
- `scripts/`: utilidades operativas (seed/reset de datos).
- `instance/curso_linux.db`: base de datos de trabajo.

## 4) Ejecución local
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Rutas:
- Portada: `http://127.0.0.1:5000/`
- Alumno: `http://127.0.0.1:5000/alumno`
- Maestro: `http://127.0.0.1:5000/teacher`

Credenciales maestro por defecto:
- Usuario: `teacher`
- Password: `ikusi2026`

## 5) Flujo funcional

### Alumno
1. Ingresa `nombre completo` y `correo`.
2. El sistema crea o reanuda sesión.
3. Responde preguntas de:
   - opción múltiple
   - análisis visual (click en imagen)
   - mini-shell simulado
4. El progreso y respuestas se guardan en tiempo real.

### Maestro
1. Monitorea sesiones en vivo.
2. Revisa respuestas recientes, distros, KPIs y análisis por alumno.
3. Puede resetear o guardar exámenes.
4. Puede consultar:
   - historial
   - análisis por alumno
   - guía de distros por número de pregunta (`/teacher/distros`)

## 6) Identidad de alumno (regla operativa importante)
- Para continuidad de métricas y puntajes acumulados, el alumno debe usar **siempre el mismo correo**.
- Recomendado también mantener **el mismo nombre** para evitar confusión visual al maestro.
- Si van a repetir intentos, volver a registrarse con los mismos datos (sobre todo el correo).

## 7) Qué hace el sistema hoy con nombre/correo
- El seguimiento histórico y ciclo de preguntas se agrupa por **correo** (llave lógica por email).
- La reanudación de una sesión *en curso* se busca por **correo**.
- Implicación práctica:
  - Si cambian el nombre pero conservan correo, mantiene historial/KPI y reanuda la sesión activa.
  - La referencia operativa principal para identidad del alumno es el correo.

## 8) Reseteo total + seed controlado (desarrollo/UAT)
Script recomendado:
- `scripts/reset_seed_5x3.py`

Este script:
- borra toda la data operativa de evaluación;
- deja solo 5 alumnos ficticios;
- inserta 3 exámenes por alumno.

Ejecución local:
```bash
python scripts/reset_seed_5x3.py
```

Ejecución UAT (ejemplo):
```bash
cd /var/www/html/CursoLinux
sudo -u www-data python3 scripts/reset_seed_5x3.py
```

## 9) Checklist de validación rápida
1. `GET /` responde 200.
2. `POST /start` crea sesión y redirige a `/exam/<token>`.
3. `GET /api/exam/<token>/state` responde item actual.
4. `POST /api/exam/<token>/answer` acepta respuestas.
5. `GET /teacher` y `/api/teacher/live` responden 200 con auth.
6. `GET /teacher/distros` muestra tabla de referencia.

## 10) Buenas prácticas para pruebas
- Usar correos ficticios consistentes por persona de prueba.
- No mezclar datos productivos con cargas masivas de QA.
- Antes de demo, limpiar DB y sembrar escenario controlado.
- Respaldar proyecto antes de cambios visuales grandes.
