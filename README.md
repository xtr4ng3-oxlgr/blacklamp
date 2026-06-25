# BLACKLAMP

<img width="1672" height="941" alt="blacklamp" src="https://github.com/user-attachments/assets/e0ef4f06-0085-4950-93b7-b40e3e5c46ba" />


**BLACKLAMP** es un escudo personal de ciberseguridad para revisar enlaces, descargas, inicios de Windows y señales locales de riesgo antes de ejecutar algo o confiar en un enlace.

Creado por **xtr4ng3**.

---

## Propósito

La seguridad personal suele fallar en el momento más simple: un clic apurado, un archivo descargado sin revisar, una extensión instalada por costumbre o un programa extraño que aparece al iniciar Windows.

BLACKLAMP existe para poner una lámpara sobre esas zonas oscuras. No intenta reemplazar un antivirus ni vender una sensación falsa de protección total. Su objetivo es mostrar señales claras, locales y entendibles para que el usuario pueda frenar antes de abrir algo riesgoso.

Todo ocurre en la máquina del usuario. No hay nube, no hay telemetría, no hay envío de enlaces, hashes ni reportes a servidores externos.

---

## Principios

- Revisión local.
- Sin telemetría.
- Sin borrado automático.
- Sin conexión a servicios externos.
- Sin cambios silenciosos en el sistema.
- Cuarentena manual con confirmación.
- Reportes legibles.
- Señales explicadas con lenguaje humano.

---

## Funciones

### Analizador de enlaces

BLACKLAMP evalúa enlaces antes de abrirlos y marca señales como uso de HTTP, acortadores, dominios con IP directa, punycode, cadenas largas de subdominios, dominios excesivamente largos, uso de `@` dentro de la URL, palabras típicas de phishing y URLs codificadas o demasiado largas.

El análisis no consulta internet. El enlace no se envía a ningún lado.

### Revisión de Descargas

Escanea una carpeta elegida por el usuario y marca archivos con señales de riesgo: ejecutables, instaladores, scripts, accesos directos, imágenes ISO/IMG, archivos de registro, dobles extensiones, nombres con palabras de alto riesgo, archivos ejecutables recientes y caracteres Unicode engañosos.

Para los archivos razonables calcula SHA-256, útil para documentar o pedir una segunda opinión.

### Cuarentena

Los archivos seleccionados pueden moverse a una carpeta local de cuarentena:

```text
quarantine/
```

BLACKLAMP no borra automáticamente. La cuarentena permite apartar un archivo sin destruirlo.

### Inicio de Windows

Revisa en modo lectura carpetas de inicio y claves `Run` / `RunOnce`. Marca señales como comandos desde Descargas, rutas en Temp, rutas en AppData, PowerShell, CMD, scripts, URLs dentro del comando, comandos codificados y ventanas ocultas.

No modifica el registro y no desactiva programas.

### Reportes

Genera reportes HTML locales con los hallazgos del enlace, archivos marcados, hashes y elementos de inicio observados.

---

## Ejecutar desde código fuente

```bash
python src/blacklamp.py
```

En Windows:

```bat
run_blacklamp.bat
```

---

## Compilar versión portable

En Windows:

```bat
build_windows\1_COMPILAR_EXE_PORTABLE.bat
```

La compilación genera una carpeta:

```text
CLIENTE_PORTABLE/
```

Dentro queda el ejecutable y las carpetas locales de datos, reportes, logs y cuarentena.

---

## Estructura

```text
BLACKLAMP/
│
├─ src/
│  └─ blacklamp.py
├─ build_windows/
├─ docs/
├─ examples/
├─ assets/
├─ README.md
├─ SECURITY.md
├─ CONTRIBUTING.md
├─ LICENSE
└─ requirements.txt
```

---

## Uso responsable

BLACKLAMP es una herramienta defensiva. No determina de forma absoluta si algo es malicioso. No reemplaza antivirus, sandboxing, análisis profesional ni criterio humano.

Un hallazgo alto significa: **detenerse y revisar**.

---

# Licencia

<img width="300" height="159" alt="giphy (25)" src="https://github.com/user-attachments/assets/021720ff-3aec-4916-9a93-25d47afd7d97" />

**xtr4ng3**

MIT.


