#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BLACKLAMP

Escudo personal de ciberseguridad para usuario común.
Analiza enlaces sospechosos, archivos riesgosos en Descargas e inicios de Windows.

Autor: xtr4ng3
Marca interna: xtr4ng3 🕷️
Licencia: MIT

Defensivo. Local. Sin nube. Sin telemetría. Sin borrado automático.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import os
import platform
import re
import shutil
import sys
import traceback
import urllib.parse
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "BLACKLAMP"
APP_VERSION = "2.0.0"
AUTHOR = "xtr4ng3"
TAG_INTERNO = "xtr4ng3 🕷️"

IS_WINDOWS = os.name == "nt"

RISKY_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".scr", ".com", ".pif", ".jar", ".hta", ".lnk", ".iso", ".img",
    ".dll", ".reg", ".cpl", ".msc", ".msp", ".cab"
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
    ".jpeg", ".png", ".zip", ".rar", ".7z"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "s.id", "rb.gy", "lnkd.in"
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "update", "secure", "security", "account",
    "wallet", "bank", "paypal", "steam", "discord", "nitro", "gift", "free",
    "premio", "regalo", "verificar", "cuenta", "soporte", "bloqueado", "urgente",
    "factura", "pago", "password", "contraseña", "token", "webhook", "airdrop", "claim", "bonus", "prize", "confirm", "unlock", "limited", "suspended"
}

HIGH_RISK_FOLDERS = [
    "downloads", "descargas", "temp", "tmp", "appdata\\roaming", "appdata\\local\\temp"
]


def app_base_dir() -> Path:
    cwd = Path.cwd()
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if exe_dir.name.upper() == "BLACKLAMP":
            return exe_dir.parent
        return exe_dir
    return cwd


BASE_DIR = app_base_dir()
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"
QUARANTINE_DIR = BASE_DIR / "quarantine"

for d in (DATA_DIR, REPORT_DIR, LOG_DIR, QUARANTINE_DIR):
    d.mkdir(parents=True, exist_ok=True)

HISTORY_PATH = DATA_DIR / "history.json"
ERROR_LOG = LOG_DIR / "errors.log"
QUARANTINE_INDEX = DATA_DIR / "quarantine_index.json"


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str


@dataclass
class LinkResult:
    original: str
    normalized: str
    host: str
    scheme: str
    score: int
    findings: List[Finding]


@dataclass
class FileFinding:
    path: str
    name: str
    extension: str
    size: int
    sha256: str
    modified: str
    score: int
    reasons: List[str]


@dataclass
class StartupFinding:
    source: str
    name: str
    command: str
    score: int
    reasons: List[str]


def log_error(exc: BaseException) -> None:
    ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
    with ERROR_LOG.open("a", encoding="utf-8") as f:
        f.write(f"\n[{dt.datetime.now().isoformat(timespec='seconds')}]\n")
        f.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))


def open_path(path: Path) -> None:
    try:
        if IS_WINDOWS:
            os.startfile(str(path))
        elif sys.platform == "darwin":
            os.system(f'open "{path}"')
        else:
            os.system(f'xdg-open "{path}"')
    except Exception as exc:
        log_error(exc)
        messagebox.showerror(APP_NAME, f"No se pudo abrir:\n{path}\n\n{exc}")


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def bytes_human(n: int) -> str:
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"




def verdict_from_score(score: int) -> str:
    if score >= 75:
        return "Crítico"
    if score >= 50:
        return "Alto"
    if score >= 25:
        return "Medio"
    if score > 0:
        return "Bajo"
    return "Limpio"

def sha256_file(path: Path, limit_mb: int = 256) -> str:
    try:
        if path.stat().st_size > limit_mb * 1024 * 1024:
            return "omitido_archivo_grande"
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "no_disponible"


def is_ip_address(host: str) -> bool:
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        try:
            return all(0 <= int(part) <= 255 for part in host.split("."))
        except Exception:
            return False
    if ":" in host and re.fullmatch(r"[0-9a-fA-F:]+", host):
        return True
    return False


def add_finding(items: List[Finding], severity: str, category: str, title: str, detail: str, recommendation: str) -> None:
    items.append(Finding(severity, category, title, detail, recommendation))


def analyze_link(raw: str) -> LinkResult:
    original = raw.strip()
    if not original:
        raise ValueError("Ingresá un enlace o dominio.")

    normalized = original
    if "://" not in normalized:
        normalized = "https://" + normalized

    parsed = urllib.parse.urlparse(normalized)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    findings: List[Finding] = []

    if scheme not in {"http", "https"}:
        add_finding(
            findings, "alta", "esquema",
            "Esquema no habitual",
            f"El enlace usa el esquema {scheme!r}.",
            "No abras enlaces con esquemas desconocidos si no entendés exactamente qué hacen."
        )

    if scheme == "http":
        add_finding(
            findings, "media", "transporte",
            "El enlace no usa HTTPS",
            "HTTP no cifra la conexión entre el navegador y el sitio.",
            "Preferí enlaces HTTPS, especialmente si hay login, pagos, cuentas o datos personales."
        )

    if not host:
        add_finding(
            findings, "alta", "formato",
            "No se pudo identificar dominio",
            "El enlace no tiene un host claro.",
            "No abras enlaces mal formados o incompletos."
        )
    else:
        if host in SHORTENERS:
            add_finding(
                findings, "media", "acortador",
                "Acortador de enlaces detectado",
                f"El dominio {host} oculta el destino real.",
                "Abrí solo si confiás en la persona que lo envió. Mejor expandirlo antes de entrar."
            )

        if is_ip_address(host):
            add_finding(
                findings, "media", "host",
                "El enlace usa una IP directa",
                "Los sitios legítimos para usuarios comunes suelen usar dominios claros.",
                "Tratala como señal de riesgo si vino por mensaje, Discord, mail o anuncio."
            )

        if "xn--" in host:
            add_finding(
                findings, "alta", "homografo",
                "Dominio punycode detectado",
                "El dominio puede contener caracteres internacionales que imitan letras comunes.",
                "Revisar con cuidado. Puede ser usado en phishing por homógrafos."
            )

        dots = host.count(".")
        if dots >= 4:
            add_finding(
                findings, "media", "subdominios",
                "Muchos subdominios",
                f"El host tiene {dots + 1} segmentos.",
                "Revisar que el dominio real sea el esperado, no solo una palabra conocida al inicio."
            )

        if len(host) > 45:
            add_finding(
                findings, "baja", "longitud",
                "Dominio largo",
                "Los dominios muy largos pueden ocultar el dominio real o confundir al usuario.",
                "Mirar el dominio principal con calma antes de abrir."
            )

        if host.count("-") >= 3:
            add_finding(
                findings, "baja", "dominio",
                "Dominio con muchos guiones",
                "Los guiones se usan a veces para imitar marcas o generar dominios confusos.",
                "Confirmar que sea el dominio oficial."
            )

    if parsed.username or parsed.password or "@" in parsed.netloc:
        add_finding(
            findings, "alta", "credenciales_url",
            "El enlace contiene @ o credenciales",
            "Puede usarse para engañar visualmente sobre el dominio real.",
            "No abras enlaces con usuario/contraseña embebidos o @ en la parte del dominio."
        )

    full_lower = normalized.lower()
    found_keywords = sorted(k for k in SUSPICIOUS_KEYWORDS if k in full_lower)
    if found_keywords:
        sev = "media" if len(found_keywords) < 4 else "alta"
        add_finding(
            findings, sev, "palabras",
            "Palabras sensibles en el enlace",
            "Coincidencias: " + ", ".join(found_keywords[:12]),
            "Desconfiá de enlaces con urgencia, premios, verificaciones, regalos, tokens o cuentas bloqueadas."
        )

    if "%" in normalized:
        add_finding(
            findings, "baja", "codificacion",
            "Caracteres codificados en URL",
            "El enlace contiene secuencias codificadas con %.",
            "Puede ser normal, pero en enlaces raros conviene revisarlo antes de abrir."
        )

    if len(normalized) > 180:
        add_finding(
            findings, "baja", "longitud",
            "URL muy larga",
            "Una URL excesivamente larga puede ocultar parámetros o destino.",
            "Revisar el dominio real y evitar abrir si llegó de una fuente no confiable."
        )

    score = 0
    for f in findings:
        if f.severity == "alta":
            score += 30
        elif f.severity == "media":
            score += 18
        elif f.severity == "baja":
            score += 7
    score = max(0, min(100, score))

    return LinkResult(original, normalized, host, scheme, score, findings)


def default_downloads() -> Path:
    home = Path.home()
    candidates = [home / "Downloads", home / "Descargas"]
    for c in candidates:
        if c.exists():
            return c
    return home


def analyze_file(path: Path) -> Optional[FileFinding]:
    try:
        if not path.is_file():
            return None

        name = path.name
        lower = name.lower()
        ext = path.suffix.lower()
        reasons: List[str] = []
        score = 0

        if ext in RISKY_EXTENSIONS:
            reasons.append(f"Extensión ejecutable o riesgosa: {ext}")
            score += 35

        parts = lower.split(".")
        if len(parts) >= 3:
            fake_ext = "." + parts[-2]
            real_ext = "." + parts[-1]
            if fake_ext in DOCUMENT_EXTENSIONS and real_ext in RISKY_EXTENSIONS:
                reasons.append("Doble extensión engañosa")
                score += 45
            elif real_ext in RISKY_EXTENSIONS:
                reasons.append("Archivo con varias extensiones y final riesgoso")
                score += 20

        if "\u202e" in name or "\u202d" in name or "\u202b" in name:
            reasons.append("Caracter Unicode de dirección de texto detectado")
            score += 45

        sensitive_words = ["crack", "keygen", "activator", "patch", "free", "nitro", "steam", "token", "cheat", "hack", "loader", "bypass", "unlocker", "premium", "gift", "airdrop", "wallet"]
        hits = [w for w in sensitive_words if w in lower]
        if hits:
            reasons.append("Nombre con palabras de alto riesgo: " + ", ".join(hits))
            score += 18

        st = path.stat()
        age_hours = (dt.datetime.now().timestamp() - st.st_mtime) / 3600
        if age_hours < 24 and ext in RISKY_EXTENSIONS:
            reasons.append("Archivo riesgoso descargado/modificado en las últimas 24 horas")
            score += 15

        if st.st_size < 4096 and ext in RISKY_EXTENSIONS:
            reasons.append("Ejecutable/script demasiado pequeño para su tipo")
            score += 10

        if not reasons:
            return None

        score = max(0, min(100, score))
        return FileFinding(
            path=str(path),
            name=name,
            extension=ext or "[sin extensión]",
            size=st.st_size,
            sha256=sha256_file(path),
            modified=dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            score=score,
            reasons=reasons,
        )
    except Exception as exc:
        log_error(exc)
        return None


def scan_downloads(folder: Path, limit: int = 2500) -> List[FileFinding]:
    results: List[FileFinding] = []
    count = 0

    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in {"node_modules", ".git", "__pycache__"}]
        for filename in files:
            count += 1
            if count > limit:
                return results
            finding = analyze_file(Path(root) / filename)
            if finding:
                results.append(finding)

    results.sort(key=lambda x: x.score, reverse=True)
    return results


def score_startup_command(command: str) -> List[str]:
    cmd = command.lower()
    reasons: List[str] = []

    for folder in HIGH_RISK_FOLDERS:
        if folder in cmd:
            reasons.append(f"Ruta de inicio ubicada en zona sensible: {folder}")

    risky = [".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".scr"]
    if any(ext in cmd for ext in risky):
        reasons.append("Inicio ejecuta script o extensión riesgosa")

    if "powershell" in cmd or "cmd.exe" in cmd or "wscript" in cmd or "cscript" in cmd:
        reasons.append("Inicio usa intérprete de comandos o scripts")

    if "http://" in cmd or "https://" in cmd:
        reasons.append("Comando de inicio contiene URL")

    if "-enc" in cmd or "encodedcommand" in cmd or "frombase64string" in cmd:
        reasons.append("PowerShell con comando codificado u ofuscado")

    if " -windowstyle hidden" in cmd or " -w hidden" in cmd:
        reasons.append("Ejecución con ventana oculta")

    return reasons


def scan_startup_items() -> List[StartupFinding]:
    results: List[StartupFinding] = []

    def add_item(source: str, name: str, command: str):
        reasons = score_startup_command(command)
        score = min(100, 15 + len(reasons) * 25) if reasons else 0
        if reasons:
            results.append(StartupFinding(source, name, command, score, reasons))

    # Startup folders
    folders = []
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", "")
        if appdata:
            folders.append(Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
        if programdata:
            folders.append(Path(programdata) / r"Microsoft\Windows\Start Menu\Programs\Startup")
    else:
        folders.append(Path.home() / ".config" / "autostart")

    for folder in folders:
        if folder.exists():
            for item in folder.iterdir():
                add_item(f"Carpeta inicio: {folder}", item.name, str(item))

    # Registry Run keys - read-only
    if IS_WINDOWS:
        try:
            import winreg
            keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            ]
            for hive, subkey, label in keys:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                add_item(label, str(name), str(value))
                                i += 1
                            except OSError:
                                break
                except OSError:
                    continue
        except Exception as exc:
            log_error(exc)

    results.sort(key=lambda x: x.score, reverse=True)
    return results


def load_history() -> List[Dict]:
    try:
        if HISTORY_PATH.exists():
            data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_history(data: List[Dict]) -> None:
    HISTORY_PATH.write_text(json.dumps(data[:200], ensure_ascii=False, indent=2), encoding="utf-8")


def load_quarantine_index() -> List[Dict]:
    try:
        if QUARANTINE_INDEX.exists():
            data = json.loads(QUARANTINE_INDEX.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_quarantine_index(data: List[Dict]) -> None:
    QUARANTINE_INDEX.write_text(json.dumps(data[:1000], ensure_ascii=False, indent=2), encoding="utf-8")


def export_html_report(link_result: Optional[LinkResult], files: List[FileFinding], startup: List[StartupFinding], path: Path) -> None:
    def sev_color(score: int) -> str:
        if score >= 70:
            return "#ff4d5e"
        if score >= 35:
            return "#ffb84d"
        return "#7ee7ff"

    link_html = "<p>No se analizó ningún enlace.</p>"
    if link_result:
        findings = "".join(
            f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.category)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.recommendation)}</td></tr>"
            for f in link_result.findings
        )
        link_html = f"""
        <h2>Enlace analizado</h2>
        <p><b>Original:</b> {html.escape(link_result.original)}</p>
        <p><b>Normalizado:</b> {html.escape(link_result.normalized)}</p>
        <p><b>Host:</b> {html.escape(link_result.host)}</p>
        <p><b>Riesgo:</b> <span style="color:{sev_color(link_result.score)}">{link_result.score}/100</span></p>
        <table><tr><th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Recomendación</th></tr>
        {findings if findings else '<tr><td colspan="4">Sin señales relevantes.</td></tr>'}
        </table>
        """

    file_rows = "".join(
        f"<tr><td style='color:{sev_color(f.score)}'>{f.score}</td><td>{html.escape(f.name)}</td><td>{html.escape(bytes_human(f.size))}</td><td>{html.escape('; '.join(f.reasons))}</td><td><code>{html.escape(f.sha256)}</code></td></tr>"
        for f in files
    )

    startup_rows = "".join(
        f"<tr><td style='color:{sev_color(s.score)}'>{s.score}</td><td>{html.escape(s.source)}</td><td>{html.escape(s.name)}</td><td><code>{html.escape(s.command)}</code></td><td>{html.escape('; '.join(s.reasons))}</td></tr>"
        for s in startup
    )

    doc = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>BLACKLAMP Reporte</title>
<style>
body{{background:#071014;color:#e8f6ff;font-family:Segoe UI,Arial;padding:30px}}
h1,h2{{color:#7ee7ff}}
.card{{background:#0d1b22;border:1px solid #1d5164;border-radius:14px;padding:18px;margin:16px 0}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}
td,th{{border-bottom:1px solid #173744;padding:9px;text-align:left;vertical-align:top}}
th{{color:#7ee7ff}}
code{{color:#d8f6ff}}
.small{{color:#9bb8c2;font-size:13px}}
</style>
</head>
<body>
<h1>BLACKLAMP</h1>
<p class="small">Escudo personal defensivo · {html.escape(AUTHOR)} · {html.escape(TAG_INTERNO)}</p>

<div class="card">{link_html}</div>

<div class="card">
<h2>Archivos riesgosos detectados</h2>
<table><tr><th>Riesgo</th><th>Nombre</th><th>Tamaño</th><th>Razones</th><th>SHA-256</th></tr>
{file_rows if file_rows else '<tr><td colspan="5">Sin archivos riesgosos en el último escaneo.</td></tr>'}
</table>
</div>

<div class="card">
<h2>Inicio de sistema observado</h2>
<table><tr><th>Riesgo</th><th>Fuente</th><th>Nombre</th><th>Comando</th><th>Razones</th></tr>
{startup_rows if startup_rows else '<tr><td colspan="5">Sin señales relevantes en inicio.</td></tr>'}
</table>
</div>

<p class="small">No borra automáticamente. No usa nube. No envía datos. Interpretar hallazgos con contexto.</p>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8")


class BlackLampApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BLACKLAMP // xtr4ng3")
        self.root.geometry("1260x800")
        self.root.minsize(1080, 680)

        self.link_var = tk.StringVar(value="")
        self.downloads_var = tk.StringVar(value=str(default_downloads()))
        self.link_result: Optional[LinkResult] = None
        self.file_results: List[FileFinding] = []
        self.startup_results: List[StartupFinding] = []
        self.file_iids: Dict[str, FileFinding] = {}
        self.history = load_history()

        self.setup_style()
        self.build_ui()
        self.log("BLACKLAMP listo. Pegá un enlace, revisá Descargas o escaneá el inicio de Windows.")

    def setup_style(self):
        self.root.configure(bg="#071014")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background="#071014", foreground="#e8f6ff", fieldbackground="#0d1b22")
        style.configure("TFrame", background="#071014")
        style.configure("Panel.TFrame", background="#0d1b22")
        style.configure("TLabel", background="#071014", foreground="#e8f6ff")
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground="#7ee7ff", background="#071014")
        style.configure("Sub.TLabel", font=("Segoe UI", 9), foreground="#9bb8c2", background="#071014")
        style.configure("Score.TLabel", font=("Segoe UI", 34, "bold"), foreground="#ffffff", background="#0d1b22")
        style.configure("Panel.TLabel", background="#0d1b22", foreground="#e8f6ff")
        style.configure("TButton", background="#102733", foreground="#e8f6ff", padding=7)
        style.map("TButton", background=[("active", "#16475d")])
        style.configure("Danger.TButton", background="#7a1020", foreground="#ffffff", padding=8)
        style.map("Danger.TButton", background=[("active", "#a3172d")])
        style.configure("Treeview", background="#0b171d", foreground="#e8f6ff", fieldbackground="#0b171d", rowheight=26)
        style.configure("Treeview.Heading", background="#102733", foreground="#7ee7ff")
        style.configure("TNotebook.Tab", background="#102733", foreground="#e8f6ff", padding=(12, 7))
        style.map("TNotebook.Tab", background=[("selected", "#16475d")], foreground=[("selected", "#ffffff")])

    def build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill=tk.X, padx=14, pady=(12, 6))
        ttk.Label(top, text="OXLGR // BLACKLAMP", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            top,
            text="Escudo personal contra enlaces raros, descargas peligrosas e inicios sospechosos · xtr4ng3",
            style="Sub.TLabel"
        ).pack(anchor="w")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=14, pady=8)

        self.tab_link = ttk.Frame(self.notebook)
        self.tab_downloads = ttk.Frame(self.notebook)
        self.tab_startup = ttk.Frame(self.notebook)
        self.tab_reports = ttk.Frame(self.notebook)
        self.tab_guide = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_link, text="Analizar enlace")
        self.notebook.add(self.tab_downloads, text="Descargas")
        self.notebook.add(self.tab_startup, text="Inicio de Windows")
        self.notebook.add(self.tab_reports, text="Reportes")
        self.notebook.add(self.tab_guide, text="Guía humana")

        self.build_link_tab()
        self.build_downloads_tab()
        self.build_startup_tab()
        self.build_reports_tab()
        self.build_guide_tab()

        bottom = ttk.Frame(self.root)
        bottom.pack(fill=tk.X, padx=14, pady=(0, 10))
        ttk.Label(bottom, text="Registro", style="Sub.TLabel").pack(anchor="w")
        self.log_box = tk.Text(bottom, height=5, bg="#050b10", fg="#d8f6ff", insertbackground="#ffffff", relief="flat")
        self.log_box.pack(fill=tk.X, pady=(4, 0))

    def build_link_tab(self):
        frame = ttk.Frame(self.tab_link)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X)
        ttk.Label(row, text="Pegá un enlace sospechoso:").pack(side=tk.LEFT, padx=4)
        ttk.Entry(row, textvariable=self.link_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(row, text="Pegar", command=self.paste_link).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="ANALIZAR", style="Danger.TButton", command=self.analyze_link_ui).pack(side=tk.LEFT, padx=4)

        cards = ttk.Frame(frame)
        cards.pack(fill=tk.X, pady=10)

        card = ttk.Frame(cards, style="Panel.TFrame")
        card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
        ttk.Label(card, text="Riesgo del enlace", style="Panel.TLabel").pack(anchor="w", padx=14, pady=(12, 0))
        self.link_score_var = tk.StringVar(value="--/100")
        ttk.Label(card, textvariable=self.link_score_var, style="Score.TLabel").pack(anchor="w", padx=14, pady=(0, 10))

        info = ttk.Frame(cards, style="Panel.TFrame")
        info.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 0))
        self.link_info_var = tk.StringVar(value="Sin análisis.")
        ttk.Label(info, textvariable=self.link_info_var, style="Panel.TLabel", wraplength=550).pack(anchor="w", padx=14, pady=14)

        self.link_tree = ttk.Treeview(frame, columns=("sev", "cat", "title", "rec"), show="headings")
        for col, title, width in [
            ("sev", "Severidad", 110),
            ("cat", "Categoría", 150),
            ("title", "Hallazgo", 360),
            ("rec", "Recomendación", 580),
        ]:
            self.link_tree.heading(col, text=title)
            self.link_tree.column(col, width=width)
        self.link_tree.pack(fill=tk.BOTH, expand=True, pady=8)

    def build_downloads_tab(self):
        frame = ttk.Frame(self.tab_downloads)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X)
        ttk.Label(row, text="Carpeta a revisar:").pack(side=tk.LEFT, padx=4)
        ttk.Entry(row, textvariable=self.downloads_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(row, text="Buscar carpeta", command=self.choose_downloads).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="ESCANEAR", style="Danger.TButton", command=self.scan_downloads_ui).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Mover seleccionados a cuarentena", command=self.quarantine_selected).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            frame,
            text="No borra automáticamente. Marca ejecutables, scripts, dobles extensiones, nombres engañosos y archivos recientes de riesgo.",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(8, 4))

        self.files_tree = ttk.Treeview(frame, columns=("score", "name", "ext", "size", "reasons", "sha"), show="headings", selectmode="extended")
        for col, title, width in [
            ("score", "Riesgo", 70),
            ("name", "Archivo", 260),
            ("ext", "Ext", 80),
            ("size", "Tamaño", 100),
            ("reasons", "Razones", 520),
            ("sha", "SHA-256", 360),
        ]:
            self.files_tree.heading(col, text=title)
            self.files_tree.column(col, width=width)
        self.files_tree.pack(fill=tk.BOTH, expand=True, pady=8)

        row2 = ttk.Frame(frame)
        row2.pack(fill=tk.X)
        ttk.Button(row2, text="Abrir cuarentena", command=lambda: open_path(QUARANTINE_DIR)).pack(side=tk.LEFT, padx=4)
        ttk.Button(row2, text="Abrir archivo seleccionado", command=self.open_selected_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(row2, text="Copiar hash", command=self.copy_selected_hash).pack(side=tk.LEFT, padx=4)

    def build_startup_tab(self):
        frame = ttk.Frame(self.tab_startup)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X)
        ttk.Button(row, text="ESCANEAR INICIO", style="Danger.TButton", command=self.scan_startup_ui).pack(side=tk.LEFT, padx=4)
        ttk.Label(
            row,
            text="Lectura defensiva. No modifica registro ni desactiva programas.",
            style="Sub.TLabel"
        ).pack(side=tk.LEFT, padx=10)

        self.startup_tree = ttk.Treeview(frame, columns=("score", "source", "name", "cmd", "reasons"), show="headings")
        for col, title, width in [
            ("score", "Riesgo", 70),
            ("source", "Fuente", 190),
            ("name", "Nombre", 180),
            ("cmd", "Comando", 520),
            ("reasons", "Razones", 360),
        ]:
            self.startup_tree.heading(col, text=title)
            self.startup_tree.column(col, width=width)
        self.startup_tree.pack(fill=tk.BOTH, expand=True, pady=8)

    def build_reports_tab(self):
        frame = ttk.Frame(self.tab_reports)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        row = ttk.Frame(frame)
        row.pack(fill=tk.X)
        ttk.Button(row, text="Exportar reporte HTML", style="Danger.TButton", command=self.export_report_ui).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Abrir reportes", command=lambda: open_path(REPORT_DIR)).pack(side=tk.LEFT, padx=4)
        ttk.Button(row, text="Abrir logs", command=lambda: open_path(LOG_DIR)).pack(side=tk.LEFT, padx=4)

        self.report_text = tk.Text(frame, bg="#050b10", fg="#d8f6ff", insertbackground="#ffffff", relief="flat", wrap="word")
        self.report_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.report_text.insert("1.0", "Los reportes se guardan localmente en reports/.\n\nBLACKLAMP no usa nube, no envía datos y no borra automáticamente.\n")
        self.report_text.config(state="disabled")

    def build_guide_tab(self):
        frame = ttk.Frame(self.tab_guide)
        frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        text = tk.Text(frame, bg="#050b10", fg="#d8f6ff", insertbackground="#ffffff", relief="flat", wrap="word")
        text.pack(fill=tk.BOTH, expand=True)
        guide = """BLACKLAMP — GUÍA HUMANA

Esta herramienta está pensada para usuario común: alguien que recibe links, descarga launchers, mods, cracks, archivos de Discord, instaladores, zips, scripts o cosas que no siempre sabe si son confiables.

QUÉ HACE:

1. Analiza enlaces
Marca señales como acortadores, dominios raros, HTTP, punycode, palabras de phishing, URLs largas, @ en el dominio y enlaces con pinta de engaño.

2. Revisa Descargas
Busca archivos con extensiones peligrosas, dobles extensiones, scripts, ejecutables recientes y nombres engañosos.

3. Revisa Inicio de Windows
Lee carpetas y claves de inicio para encontrar comandos raros, scripts, PowerShell, rutas en AppData/Temp/Downloads o inicios sospechosos.

4. Cuarentena
Puede mover archivos seleccionados a quarantine/. No borra automáticamente.

5. Reportes
Genera un reporte HTML local para guardar o pedir ayuda a alguien técnico.

REGLA SIMPLE:
Si BLACKLAMP marca algo alto, no lo abras. Revisalo, preguntá o subilo a un servicio de análisis conocido desde tu navegador, si sabés lo que estás haciendo.

NO ES ANTIVIRUS:
Es una capa de criterio. Te ayuda a no hacer clic o ejecutar cosas peligrosas.

Marca interna: xtr4ng3 🕷️
"""
        text.insert("1.0", guide)
        text.config(state="disabled")

    def paste_link(self):
        try:
            self.link_var.set(self.root.clipboard_get())
        except Exception:
            pass

    def analyze_link_ui(self):
        try:
            result = analyze_link(self.link_var.get())
            self.link_result = result
            self.link_tree.delete(*self.link_tree.get_children())

            for f in result.findings:
                self.link_tree.insert("", tk.END, values=(f.severity, f.category, f.title, f.recommendation))

            self.link_score_var.set(f"{result.score}/100")
            if result.score >= 75:
                msg = "Crítico. No abras este enlace sin verificarlo por otro medio."
            elif result.score >= 50:
                msg = "Alto. Revisar con cuidado antes de abrir."
            elif result.score >= 25:
                msg = "Medio. Hay señales que merecen atención."
            elif result.findings:
                msg = "Bajo. Hay detalles menores para revisar."
            else:
                msg = "Sin señales fuertes con reglas locales. Igual importa el contexto."
            self.link_info_var.set(f"{msg}\nHost: {result.host}\nURL normalizada: {result.normalized}")
            self.log(f"Enlace analizado: {result.host} · riesgo {result.score}/100")
            self.add_history("link", result.score, result.normalized)
        except Exception as exc:
            log_error(exc)
            messagebox.showerror(APP_NAME, str(exc))

    def choose_downloads(self):
        folder = filedialog.askdirectory(title="Seleccionar carpeta")
        if folder:
            self.downloads_var.set(folder)

    def scan_downloads_ui(self):
        folder = Path(self.downloads_var.get().strip() or str(default_downloads()))
        if not folder.exists():
            messagebox.showerror(APP_NAME, "La carpeta no existe.")
            return

        self.log(f"Escaneando carpeta: {folder}")
        self.file_results = scan_downloads(folder)
        self.file_iids.clear()
        self.files_tree.delete(*self.files_tree.get_children())

        for f in self.file_results:
            iid = self.files_tree.insert("", tk.END, values=(
                f.score,
                f.name,
                f.extension,
                bytes_human(f.size),
                "; ".join(f.reasons),
                f.sha256,
            ))
            self.file_iids[iid] = f

        self.log(f"Escaneo de descargas completado: {len(self.file_results)} archivos marcados.")
        self.add_history("downloads", len(self.file_results), str(folder))

    def quarantine_selected(self):
        selected = self.files_tree.selection()
        if not selected:
            messagebox.showwarning(APP_NAME, "Seleccioná archivos primero.")
            return

        if not messagebox.askyesno(APP_NAME, f"¿Mover {len(selected)} archivos a cuarentena?\nNo se borrarán definitivamente."):
            return

        dest_root = QUARANTINE_DIR / f"blacklamp_{now_stamp()}"
        dest_root.mkdir(parents=True, exist_ok=True)
        quarantine_index = load_quarantine_index()

        moved = 0
        failed = 0

        for iid in selected:
            item = self.file_iids.get(iid)
            if not item:
                continue
            src = Path(item.path)
            try:
                if not src.exists() or not src.is_file():
                    failed += 1
                    continue
                dest = dest_root / src.name
                if dest.exists():
                    dest = dest_root / f"{src.stem}_{int(dt.datetime.now().timestamp())}{src.suffix}"
                shutil.move(str(src), str(dest))
                quarantine_index.insert(0, {
                    "date": dt.datetime.now().isoformat(timespec="seconds"),
                    "original": str(src),
                    "quarantine": str(dest),
                    "sha256": item.sha256,
                    "reasons": item.reasons,
                })
                moved += 1
                self.files_tree.delete(iid)
            except Exception as exc:
                failed += 1
                log_error(exc)

        save_quarantine_index(quarantine_index)
        self.log(f"Cuarentena completada: movidos={moved}, fallidos={failed}.")
        open_path(dest_root)

    def open_selected_file(self):
        selected = self.files_tree.selection()
        if not selected:
            return
        item = self.file_iids.get(selected[0])
        if item:
            open_path(Path(item.path).parent)

    def copy_selected_hash(self):
        selected = self.files_tree.selection()
        if not selected:
            return
        item = self.file_iids.get(selected[0])
        if item:
            self.root.clipboard_clear()
            self.root.clipboard_append(item.sha256)
            self.log("SHA-256 copiado al portapapeles.")

    def scan_startup_ui(self):
        self.log("Escaneando inicio del sistema...")
        self.startup_results = scan_startup_items()
        self.startup_tree.delete(*self.startup_tree.get_children())

        for s in self.startup_results:
            self.startup_tree.insert("", tk.END, values=(
                s.score,
                s.source,
                s.name,
                s.command,
                "; ".join(s.reasons),
            ))

        self.log(f"Escaneo de inicio completado: {len(self.startup_results)} elementos marcados.")
        self.add_history("startup", len(self.startup_results), platform.node())

    def export_report_ui(self):
        path = REPORT_DIR / f"blacklamp_report_{now_stamp()}.html"
        export_html_report(self.link_result, self.file_results, self.startup_results, path)
        self.log(f"Reporte exportado: {path}")
        open_path(path)

    def add_history(self, kind: str, score: int, subject: str):
        self.history.insert(0, {
            "date": dt.datetime.now().isoformat(timespec="seconds"),
            "kind": kind,
            "score": score,
            "subject": subject,
        })
        self.history = self.history[:200]
        save_history(self.history)

    def log(self, text):
        line = f"[{dt.datetime.now().strftime('%H:%M:%S')}] {text}"
        try:
            self.log_box.insert(tk.END, line + "\n")
            self.log_box.see(tk.END)
        except Exception:
            pass

    def run(self):
        self.root.mainloop()


def main():
    try:
        app = BlackLampApp()
        app.run()
    except Exception as exc:
        log_error(exc)
        try:
            messagebox.showerror(APP_NAME, f"Error crítico:\n{exc}\n\nRevisar logs/errors.log")
        except Exception:
            print(exc)


if __name__ == "__main__":
    main()
