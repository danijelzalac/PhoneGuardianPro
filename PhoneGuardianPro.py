
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phone Guardian Pro — Professional CLI
Single-file Rich TUI wrapper around MVT's `check-adb` for indicative Android checks.
- Linux-focused; robust on Bazzite/Fedora Atomic (non-destructive auto-setup hints).
- Python 3.10–3.13 (3.11 preferred).
- Minimal deps: rich (auto-vendored to ./_vendor if missing), optional curses.

Author: Danijel Žalac (2025) • Special thanks: MVT, Amnesty International Security Lab
Project repo: https://github.com/danijelzalac/PhoneGuardianPro
User Guide:   https://github.com/danijelzalac/PhoneGuardianPro/wiki/HomePhoneGuardianPro-%E2%80%93-User-Guide
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ───────────────────────────── App root & vendor bootstrap ────────────────────

def _resolve_app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

APP_ROOT = _resolve_app_root()
VENDOR_DIR = APP_ROOT / "_vendor"
VENDOR_DIR.mkdir(parents=True, exist_ok=True)

def _ensure_rich_available() -> None:
    try:
        import rich  # type: ignore
        return
    except Exception:
        pass
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade",
             "--no-warn-script-location", "--target", str(VENDOR_DIR), "rich"],
            check=False, capture_output=True, text=True)
    except Exception:
        pass

if str(VENDOR_DIR) not in sys.path:
    sys.path.insert(0, str(VENDOR_DIR))
_ensure_rich_available()

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except Exception:
    print(
        "This program requires the 'rich' package.\n"
        "We tried to auto-install into ./_vendor but failed.\n"
        "Fix with:\n  python3 -m pip install --user rich\n"
        "or\n  python3 -m pip install --target ./_vendor rich",
        file=sys.stderr,
    )
    sys.exit(2)

# Optional curses (arrow-key menu)
try:
    import curses  # type: ignore
    _HAVE_CURSES = True
except Exception:
    _HAVE_CURSES = False

# urllib no longer needed (we removed portable platform-tools downloads)

# ───────────────────────────── Constants / portable paths ─────────────────────

APP_NAME = "Phone Guardian Pro — Professional CLI"
APP_SHORT = "Phone Guardian Pro"
APP_VERSION = "4.2.0"

LOGS_DIR     = APP_ROOT / "logs"
REPORTS_DIR  = APP_ROOT / "reports"
VENV_DIR     = APP_ROOT / "pgp-venv"                  # optional local venv (fallback)
DATA_HOME    = APP_ROOT / "data"                      # optional local XDG_DATA_HOME
LOCAL_INDICATORS_DIR   = DATA_HOME / "mvt" / "indicators"
DEFAULT_INDICATORS_DIR = Path.home() / ".local" / "share" / "mvt" / "indicators"
MODULES_TXT  = APP_ROOT / "modules_detected.txt"

REPO_URL = "https://github.com/danijelzalac/PhoneGuardianPro"
WIKI_URL = "https://github.com/danijelzalac/PhoneGuardianPro/wiki/HomePhoneGuardianPro-%E2%80%93-User-Guide"

for d in (LOGS_DIR, REPORTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

ACCENTS = {"teal": "turquoise2", "blue": "dodger_blue2", "purple": "medium_purple"}
DEFAULT_ACCENT = "teal"
HIT_TYPES = {"none", "min", "all"}

# Deprecated URL retained earlier is no longer used; remove constant entirely

console = Console(highlight=False, soft_wrap=False, emoji=True)

def _nowstamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

LOG_FILE = LOGS_DIR / f"PGP_{_nowstamp()}.log"
_LOG_FH = open(LOG_FILE, "w", encoding="utf-8", buffering=1)

def _log_line(s: str) -> None:
    _LOG_FH.write(f"[{datetime.now().isoformat(timespec='seconds')}] {s.rstrip()}\n")
    _LOG_FH.flush()

# ───────────────────────────── Helpers / PATH / env ───────────────────────────

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def venv_bin_dir() -> Path:
    return (VENV_DIR / "bin")

def _is_executable(p: Path) -> bool:
    try:
        return p.exists() and p.is_file() and os.access(str(p), os.X_OK)
    except Exception:
        return False

def find_adb_bin() -> Optional[Path]:
    adb_path = which("adb")
    if adb_path:
        return Path(adb_path)
    # Probe common Windows locations if PATH lookup failed
    try:
        if os.name == "nt":
            candidates: List[Path] = []
            local_appdata = os.environ.get("LOCALAPPDATA")
            userprofile = os.environ.get("USERPROFILE")
            program_files = os.environ.get("ProgramFiles")
            if local_appdata:
                candidates.append(Path(local_appdata) / "Android" / "Sdk" / "platform-tools" / "adb.exe")
            if userprofile:
                candidates.append(Path(userprofile) / "AppData" / "Local" / "Android" / "Sdk" / "platform-tools" / "adb.exe")
            if program_files:
                candidates.append(Path(program_files) / "Android" / "platform-tools" / "adb.exe")
            for cand in candidates:
                if _is_executable(cand):
                    return cand
    except Exception:
        pass
    return None

def find_mvt_bin() -> Optional[Path]:
    local = venv_bin_dir() / "mvt-android"
    if _is_executable(local):
        return local
    mvt_path = which("mvt-android")
    return Path(mvt_path) if mvt_path else None

def env_for_mvt() -> Dict[str, str]:
    """
    Default to MVT's own location (~/.local/share/mvt) per spec.
    Only override XDG_DATA_HOME if the local ./data tree already exists
    (portability) or user explicitly opts in via PGP_USE_LOCAL_DATA=1.
    """
    env = os.environ.copy()
    path_items = []
    vb = venv_bin_dir()
    if vb.exists():
        path_items.append(str(vb))
    path_items.append(env.get("PATH", ""))
    env["PATH"] = ":".join(path_items)

    if os.environ.get("PGP_USE_LOCAL_DATA") == "1" or LOCAL_INDICATORS_DIR.exists():
        (LOCAL_INDICATORS_DIR).mkdir(parents=True, exist_ok=True)
        env["XDG_DATA_HOME"] = str(DATA_HOME)
    return env

# ───────────────────────────── Subprocess wrapper ─────────────────────────────

def run_cmd(
    cmd: Sequence[str] | str,
    *,
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
    echo: bool = True,
) -> Tuple[int, str]:
    """Run a command robustly; stream stdout/stderr to console and log; never raise."""
    if isinstance(cmd, (list, tuple)):
        printable = " ".join(shlex.quote(x) for x in cmd)
        popen_args = dict(shell=False)
    else:
        # Disallow string commands to avoid shell differences and injection risks
        raise ValueError("run_cmd requires Sequence[str], not str")
    if echo:
        console.print(f"[dim]$ {printable}[/]")
    _log_line(f"$ {printable}")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env or os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=timeout,
            **popen_args,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if out:
            for line in out.splitlines():
                console.print(line)
                _log_line(line)
        return proc.returncode, out
    except Exception as e:
        msg = f"Command failed: {e}"
        console.print(f"[red]{msg}[/]")
        _log_line(msg)
        return 1, ""

# ───────────────────────────── Accent / UI blocks ────────────────────────────

def _phone_shield_ascii() -> str:
    # A compact banner instead of wide ASCII blocks; looks good on 80+ cols.
    return "\n".join([
        "   ╭───────────────╮      Phone Guardian Pro",
        "   │  📱  🛡️  PGP  │      Indicative Android checks over ADB using MVT",
        "   ╰───────────────╯      Made by Danijel Žalac • Special thanks: MVT & Amnesty International",
    ])

def banner(accent: str) -> None:
    body = Text.from_markup(_phone_shield_ascii())
    header = Panel(
        Align.left(body),
        border_style=accent,
        box=box.HEAVY,
        padding=(1,2),
    )
    console.print(header)

def chips_line(names: Iterable[str], accent: str) -> None:
    items = []
    for n in names:
        items.append(f"[black on {accent}]●[/] [b]{n}[/]")
    console.print("  ".join(items))

# ───────────────────────────── IOC helpers ───────────────────────────────────

KNOWN_NAME_MAP = {
    "pegasus": "NSO Group Pegasus",
    "predator": "Intellexa Predator",
    "rcs": "RCS Lab RCS",
    "stalkerware": "Stalkerware (generic)",
    "2023-03-29_android_campaign_malware": "Mercenary spyware campaign (Amnesty 2023-03-29)",
    "quadream": "Quadream KingSpawn",
    "triangulation": "Operation Triangulation",
    "wyrmspy": "WyrmSpy",
    "dragonegg": "DragonEgg",
    "wintego": "Wintego Helios",
    "novispy": "NoviSpy (Serbia)",
    "candiru": "Candiru (DevilsTongue)",
    "devilstongue": "Candiru (DevilsTongue)",
    "helios": "Wintego Helios",
    "finspy": "FinFisher FinSpy",
    "xloader": "XLoader",
    "hermit": "RCS Lab Hermit",
    "kingo": "Kingo Root (abuse)",
}

def ioc_dirs() -> List[Path]:
    dirs: List[Path] = []
    if DEFAULT_INDICATORS_DIR.exists():
        dirs.append(DEFAULT_INDICATORS_DIR)
    if LOCAL_INDICATORS_DIR.exists():
        dirs.append(LOCAL_INDICATORS_DIR)
    return dirs

def list_installed_iocs() -> List[Path]:
    files: List[Path] = []
    for d in ioc_dirs():
        for p in sorted(d.glob("*.stix2")):
            if p not in files:
                files.append(p)
    return files

def friendly_ioc_name(p: Path) -> str:
    low = p.name.lower()
    for k, v in KNOWN_NAME_MAP.items():
        if k in low:
            return v
    return p.stem.replace("_", " ").strip()

def header_known_sets(max_items: int = 8) -> List[str]:
    names = [friendly_ioc_name(p) for p in list_installed_iocs()]
    # Keep unique order and cap
    seen, out = set(), []
    for n in names:
        if n not in seen:
            out.append(n); seen.add(n)
        if len(out) >= max_items:
            break
    if not out:
        out = [
            "Intellexa Predator", "NoviSpy (Serbia)", "NSO Group Pegasus",
            "Quadream KingSpawn", "Wintego Helios", "WyrmSpy",
            "Candiru (DevilsTongue)", "RCS Lab RCS",
        ]
    return out[:max_items]

# ───────────────────────────── Env / Quick checks ────────────────────────────

def detect_python() -> Tuple[bool, str]:
    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    ok = (3,10) <= (sys.version_info.major, sys.version_info.minor) <= (3,13)
    return ok, ver

def detect_adb() -> Tuple[bool, str]:
    adb = find_adb_bin()
    if not adb:
        return False, "not found"
    rc, out = run_cmd([str(adb), "version"], echo=False)
    if rc == 0 and out:
        first = out.splitlines()[0].strip()
        return True, first
    return False, "not working"

def parse_mvt_version(help_text: str) -> Optional[str]:
    m = re.search(r"Version:\s*([0-9.]+)", help_text, re.I)
    return m.group(1) if m else None

def detect_mvt() -> Tuple[bool, str]:
    mvt = find_mvt_bin()
    if not mvt:
        return False, "mvt-android not found"
    rc, out = run_cmd([str(mvt), "check-adb", "--help"], echo=False, env=env_for_mvt())
    if rc != 0:
        return False, "mvt-android not working"
    ver = parse_mvt_version(out) or "unknown"
    return True, ver

def quick_checks_ui(accent: str) -> None:
    ok_py, py = detect_python()
    ok_adb, adb = detect_adb()
    ok_mvt, mvt = detect_mvt()
    iocs = list_installed_iocs()
    counts = [f"{len(list(d.glob('*.stix2')))} @ {d}" for d in ioc_dirs()] or [f"0 @ {DEFAULT_INDICATORS_DIR}"]
    tbl = Table(box=box.HEAVY, show_lines=False, title="Quick Checks")
    tbl.add_column("Item", style="bold")
    tbl.add_column("Details")
    tbl.add_column("OK?", justify="center")
    tbl.add_row("Python", py, "✅" if ok_py else "❌")
    tbl.add_row("ADB", adb, "✅" if ok_adb else "❌")
    tbl.add_row("MVT-Android", mvt if ok_mvt else "mvt-android missing", "✅" if ok_mvt else "❌")
    tbl.add_row("IOCs", "; ".join(counts), "✅" if iocs else "❌")
    console.print(tbl)
    if not iocs:
        console.print(Panel("No IOC files detected. Run [b]Update IOCs[/].", border_style="yellow"))

# ───────────────────────────── ADB / MVT wrappers ────────────────────────────

def adb_devices_table(accent: str) -> None:
    adb = find_adb_bin()
    if not adb:
        console.print(Panel(
            "ADB not found on PATH. Install it via your package manager:\n\n"
            "Linux:\n"
            "• Fedora/RHEL: sudo dnf install -y android-tools\n"
            "• Debian/Ubuntu: sudo apt install -y android-tools-adb\n"
            "• Arch: sudo pacman -S android-tools\n\n"
            "Windows:\n"
            "• winget: winget install --id Google.PlatformTools --source winget\n"
            "• Chocolatey: choco install adb\n"
            "• ZIP: https://dl.google.com/android/repository/platform-tools-latest-windows.zip (add to PATH)\n\n"
            "Then re-run this command.",
            border_style="red"
        ))
        return
    rc, out = run_cmd([str(adb), "devices", "-l"])
    lines = [l for l in (out.splitlines() if out else []) if l.strip() and not l.lower().startswith("list of devices")]
    tbl = Table(box=box.HEAVY, title="ADB Devices")
    tbl.add_column("#", justify="right")
    tbl.add_column("Descriptor")
    for i, l in enumerate(lines, 1):
        tbl.add_row(str(i), l)
    if not lines:
        console.print(Panel("No devices visible. Enable USB debugging and accept RSA fingerprint.", border_style="yellow"))
    console.print(tbl)

def mvt_download_iocs_ui(accent: str) -> None:
    mvt = find_mvt_bin()
    if not mvt:
        console.print(Panel(
            "mvt-android not found. Install MVT at the user/system level:\n\n"
            "• pipx: pipx install mvt\n"
            "• pip (user): pip3 install --user mvt\n\n"
            "On Fedora Atomic/Bazzite, see Manual for Toolbox instructions.",
            border_style="red"
        ))
        return
    console.print(Panel("Updating IOCs…", border_style=accent))
    rc, _ = run_cmd([str(mvt), "download-iocs"], env=env_for_mvt())
    total = len(list_installed_iocs())
    locs = "; ".join(str(d) for d in ioc_dirs()) or str(DEFAULT_INDICATORS_DIR)
    border = "green" if rc == 0 else "red"
    console.print(Panel(f"IOCs update complete. {total} file(s) present.\nLocation(s): {locs}", border_style=border))

def mvt_list_modules() -> Tuple[List[str], str]:
    mvt = find_mvt_bin()
    if not mvt:
        return [], ""
    rc, out = run_cmd([str(mvt), "check-adb", "--list-modules"], env=env_for_mvt())
    mods: List[str] = []
    for line in (out.splitlines() if out else []):
        m = re.search(r"-\s+([A-Za-z0-9_]+)\s*$", line.strip())
        if m:
            mods.append(m.group(1))
    return mods, out or ""

    

def guided_setup_wizard(accent: str) -> None:
    """Simple 3-step guided setup: prerequisites → device → IOCs."""
    # Step 1: prerequisites
    console.print(Panel("Step 1/3 — Prerequisites", border_style=accent))
    ok_py, py = detect_python()
    ok_adb, adb = detect_adb()
    ok_mvt, mvt = detect_mvt()
    tbl = Table(box=box.HEAVY, title="Checks")
    tbl.add_column("Item", style="bold"); tbl.add_column("Details"); tbl.add_column("OK?", justify="center")
    tbl.add_row("Python", py, "✅" if ok_py else "❌")
    tbl.add_row("ADB", adb, "✅" if ok_adb else "❌")
    tbl.add_row("MVT-Android", mvt if ok_mvt else "mvt-android missing", "✅" if ok_mvt else "❌")
    console.print(tbl)
    console.print(Panel("Press ENTER to continue…", border_style=accent));
    try: input()
    except EOFError: return

    # Step 2: device connection
    console.print(Panel("Step 2/3 — Connect your Android device (USB debugging enabled)", border_style=accent))
    adb_devices_table(accent)
    console.print(Panel("After enabling USB debugging and accepting the RSA prompt, press ENTER to re-check.", border_style=accent))
    try: input()
    except EOFError: return
    adb_devices_table(accent)

    # Vendor-specific hints (e.g., Xiaomi often restricts adb access on stock ROMs)
    props = get_device_props()
    vendor = (props.get("ro.product.manufacturer","") or "").lower()
    if "xiaomi" in vendor or "redmi" in vendor or "poco" in vendor:
        console.print(Panel(
            "Note for Xiaomi/Redmi/POCO: If you see 'device is busy' or permission issues, ensure:\n"
            "• USB debugging is enabled and RSA prompt accepted.\n"
            "• Try 'adb kill-server && adb start-server' and reconnect.\n"
            "Some MIUI builds limit access without additional steps.",
            border_style="yellow"
        ))

    # Step 3: IOCs
    console.print(Panel("Step 3/3 — Update Indicators of Compromise (IOCs)", border_style=accent))
    mvt_download_iocs_ui(accent)
    console.print(Panel("Guided setup complete.", border_style="green"))

def list_modules_ui(accent: str) -> None:
    mods, raw = mvt_list_modules()
    if not mods:
        console.print(Panel("No modules detected or mvt-android missing.", border_style="red"))
        return
    MODULES_TXT.write_text(raw, encoding="utf-8")
    tbl = Table(box=box.HEAVY, title="MVT Modules")
    tbl.add_column("#", justify="right")
    tbl.add_column("Module")
    for i, m in enumerate(mods, 1):
        tbl.add_row(str(i), m)
    console.print(tbl)
    console.print(Panel(f"Saved raw output to {MODULES_TXT}", border_style="green"))

# ───────────────────────────── Hit parsing / status ──────────────────────────

HIT_KEYWORDS = {
    "domain": r"\bdomain|hostname|dns\b",
    "url": r"\burl|https?://\b",
    "ip": r"\bip(v4|v6)?\b",
    "file": r"\bfile|path\b",
    "package": r"\bpackage|pkg\b",
    "process": r"\bprocess|ps\b",
}

@dataclass
class ModuleOutcome:
    module: str
    status: str  # CLEAN | HITS | SKIPPED | FAILED
    reason: str = ""
    defs: int = 0
    hits_total: int = 0
    hit_types: Dict[str, int] = field(default_factory=dict)

def parse_indicator_defs(stdout: str) -> int:
    m = re.search(r"Loaded a total of\s*(\d+)\s*unique indicators", stdout, re.I)
    return int(m.group(1)) if m else 0

def classify_stdout(stdout: str) -> Tuple[str, str]:
    s = stdout.lower()
    if "device is busy" in s:
        return "FAILED", "ADB busy; run 'adb kill-server' and 'adb start-server'."
    if re.search(r"unauthorized", s):
        return "FAILED", "Device unauthorized — unlock phone and accept RSA fingerprint."
    if re.search(r"device offline", s):
        return "FAILED", "Device offline — reconnect cable and ensure USB debugging is enabled."
    if re.search(r"permission denied|not permitted|root|access denied|no such table: history", s):
        return "SKIPPED", "not rooted/no permission"
    if re.search(r"error:|traceback|exception|failed|critical", s):
        return "FAILED", "unexpected tool error"
    if re.search(r"\bmatch|indicator hit|suspicious|ioc\b", s):
        return "HITS", ""
    return "CLEAN", ""

def _is_adb_busy(status: str, reason: str) -> bool:
    s = f"{status} {reason}".lower()
    return (status == "FAILED") and ("busy" in s or "device is busy" in s)

def count_hits_in_files(paths: List[Path]) -> Tuple[int, Dict[str, int]]:
    total = 0
    per_type: Dict[str, int] = {}
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            text = ""
        if p.suffix.lower() == ".json":
            total += len(re.findall(r'"match(ed)?_?(indicator)?"\s*:\s*(true|"true"|1)', text, re.I))
            for k, pat in HIT_KEYWORDS.items():
                c = len(re.findall(pat, text, re.I))
                if c:
                    per_type[k] = per_type.get(k, 0) + c
        elif p.suffix.lower() in (".csv", ".tsv"):
            try:
                import csv
                with p.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
                    dialect = csv.excel
                    sample = fh.read(1024)
                    fh.seek(0)
                    try:
                        dialect = csv.Sniffer().sniff(sample)
                    except Exception:
                        pass
                    reader = csv.reader(fh, dialect)
                    _ = next(reader, [])
                    for row in reader:
                        total += 1
                        row_text = " ".join(row)
                        for k, pat in HIT_KEYWORDS.items():
                            if re.search(pat, row_text, re.I):
                                per_type[k] = per_type.get(k, 0) + 1
            except Exception:
                pass
        else:
            for k, pat in HIT_KEYWORDS.items():
                c = len(re.findall(pat, text, re.I))
                if c:
                    per_type[k] = per_type.get(k, 0) + c
    return total, per_type

def new_files_since(dirpath: Path, before: float) -> List[Path]:
    files: List[Path] = []
    for p in dirpath.rglob("*"):
        try:
            if p.is_file() and p.stat().st_mtime >= before - 0.5:
                files.append(p)
        except Exception:
            continue
    return files

# ───────────────────────────── Scanning flows ────────────────────────────────

def adb_quick_reset() -> None:
    adb = find_adb_bin()
    if not adb:
        return
    run_cmd([str(adb), "kill-server"], echo=False)
    time.sleep(0.1)
    run_cmd([str(adb), "start-server"], echo=False)
    # Ensure the next call sees a ready device if connected
    run_cmd([str(adb), "wait-for-device"], echo=False)

def adb_ensure_ready(max_attempts: int = 2) -> bool:
    """Try to bring ADB and device to a ready state. Returns True if shell works."""
    adb = find_adb_bin()
    if not adb:
        return False
    for attempt in range(1, max_attempts + 1):
        # Basic listing
        run_cmd([str(adb), "devices", "-l"], echo=False)
        # Quick reset + wait
        run_cmd([str(adb), "kill-server"], echo=False)
        time.sleep(0.2)
        run_cmd([str(adb), "start-server"], echo=False)
        run_cmd([str(adb), "wait-for-device"], echo=False)
        # Try reconnect helpers (supported on recent adb)
        run_cmd([str(adb), "reconnect"], echo=False)
        run_cmd([str(adb), "usb"], echo=False)
        # Probe simple shell
        rc, _ = run_cmd([str(adb), "shell", "echo", "ok"], echo=False)
        if rc == 0:
            return True
        time.sleep(0.5)
    return False

def get_device_props() -> Dict[str, str]:
    props = {
        "ro.product.manufacturer": "",
        "ro.product.model": "",
        "ro.build.version.release": "",
        "ro.build.version.sdk": "",
        "ro.build.fingerprint": "",
    }
    adb = find_adb_bin()
    if not adb:
        return props
    for k in list(props.keys()):
        rc, out = run_cmd([str(adb), "shell", "getprop", k], echo=False)
        if rc == 0:
            props[k] = (out or "").strip().splitlines()[0] if out else ""
    return props

def write_summary(outdir: Path, outcomes: List[ModuleOutcome], props: Dict[str, str]) -> None:
    by_type: Dict[str, int] = {}
    for oc in outcomes:
        for t, n in oc.hit_types.items():
            by_type[t] = by_type.get(t, 0) + n
    lines: List[str] = []
    lines.append(f"{APP_SHORT} summary — {datetime.now().isoformat(timespec='seconds')}")
    ok_mvt, mvt_ver = detect_mvt()
    ok_adb, adb_ver = detect_adb()
    lines.append(f"MVT: {'present' if ok_mvt else 'missing'} ({mvt_ver})")
    lines.append(f"ADB: {'present' if ok_adb else 'missing'} ({adb_ver})")
    lines.append("")
    lines.append("Device info:")
    for k, v in props.items():
        lines.append(f"  {k}: {v}")
    lines.append("")
    lines.append("Modules run:")
    for oc in outcomes:
        suffix = ""
        if oc.status == "HITS":
            suffix = f" — hits: {oc.hits_total}"
        elif oc.status in ("FAILED", "SKIPPED") and oc.reason:
            suffix = f" — {oc.reason}"
        lines.append(f"  {oc.module}: {oc.status}{suffix}")
    lines.append("")
    if by_type:
        lines.append("Hit counts by type:")
        for t, n in sorted(by_type.items()):
            lines.append(f"  {t}: {n}")
    out = "\n".join(lines) + "\n"
    (outdir / "summary.txt").write_text(out, encoding="utf-8")

def scan_all_modules(accent: str, hit_mode: str) -> None:
    mvt = find_mvt_bin()
    if not mvt:
        console.print(Panel("mvt-android not found.", border_style="red"))
        return
    outdir = REPORTS_DIR / f"android_{_nowstamp()}"
    outdir.mkdir(parents=True, exist_ok=True)
    adb_quick_reset()
    adb_ensure_ready()
    before = time.time()
    console.print(Panel("Starting scan (all modules)…", border_style=accent))
    rc, out = run_cmd([str(mvt), "check-adb", "--non-interactive", "--output", str(outdir)], env=env_for_mvt())
    defs = parse_indicator_defs(out)
    status, reason = classify_stdout(out)
    # Retry once if adb appears busy
    if _is_adb_busy(status, reason):
        adb_quick_reset()
        adb_ensure_ready()
        rc, out = run_cmd([str(mvt), "check-adb", "--non-interactive", "--output", str(outdir)], env=env_for_mvt())
        defs = parse_indicator_defs(out)
        status, reason = classify_stdout(out)
    new = new_files_since(outdir, before)
    hits, by_type = count_hits_in_files(new)
    color = "green" if status == "CLEAN" else ("red" if status == "FAILED" else ("yellow" if status == "SKIPPED" else ACCENTS.get('teal','turquoise2')))
    headline = f"Status: {status}"
    if status == "HITS":
        headline = f"[b]{headline}: {hits}[/b]"
    if status in ("FAILED", "SKIPPED") and reason:
        headline += f" — {reason}"
    extra = f"defs: {defs}"
    if status == "HITS" and hit_mode != "none":
        types_list = ", ".join(sorted(by_type.keys())) if hit_mode == "all" else ", ".join(sorted(by_type.keys())[:3])
        if types_list:
            extra += f" • types: {types_list}"
    console.print(Panel(f"{headline}\n{extra}\nReports: {outdir}", border_style=color))
    props = get_device_props()
    outcomes = [ModuleOutcome(module="ALL", status=status, reason=reason, defs=defs, hits_total=hits, hit_types=by_type)]
    write_summary(outdir, outcomes, props)
    console.print(Panel("summary.txt saved.", border_style="green"))

def scan_module_by_module(accent: str, hit_mode: str) -> None:
    mvt = find_mvt_bin()
    mods, _ = mvt_list_modules()
    if not mods or not mvt:
        console.print(Panel("No modules detected or mvt-android missing.", border_style="red"))
        return
    outdir = REPORTS_DIR / f"android_{_nowstamp()}"
    outdir.mkdir(parents=True, exist_ok=True)
    outcomes: List[ModuleOutcome] = []
    for idx, mod in enumerate(mods, 1):
        console.print(Panel(f"({idx}/{len(mods)}) Module: [b]{mod}[/b]", border_style=accent))
        adb_quick_reset()
        before = time.time()
        rc, out = run_cmd([str(mvt), "check-adb", "--non-interactive", "--output", str(outdir), "--module", mod], env=env_for_mvt())
        defs = parse_indicator_defs(out)
        status, reason = classify_stdout(out)
        if _is_adb_busy(status, reason):
            adb_quick_reset()
            adb_ensure_ready()
            rc, out = run_cmd([str(mvt), "check-adb", "--non-interactive", "--output", str(outdir), "--module", mod], env=env_for_mvt())
            defs = parse_indicator_defs(out)
            status, reason = classify_stdout(out)
        new = new_files_since(outdir, before)
        hits, by_type = count_hits_in_files(new)
        oc = ModuleOutcome(module=mod, status=status, reason=reason, defs=defs, hits_total=hits, hit_types=by_type)
        outcomes.append(oc)
        if status == "CLEAN":
            msg = "CLEAN"; border = "green"
        elif status == "HITS":
            msg = f"[b]HITS: {hits}[/b]"; border = ACCENTS.get('teal','turquoise2')
        elif status == "SKIPPED":
            msg = f"SKIPPED — {reason or 'not rooted/no permission'}"; border = "yellow"
        else:
            remedy = reason or "ADB busy; run 'adb kill-server' and 'adb start-server'."
            msg = f"FAILED — {remedy}"; border = "red"
        extra = f"defs: {defs}"
        if status == "HITS" and hit_mode != "none":
            types_list = ", ".join(sorted(by_type.keys())) if hit_mode == "all" else ", ".join(sorted(by_type.keys())[:3])
            if types_list:
                extra += f" • types: {types_list}"
        console.print(Panel(f"{msg}\n{extra}", border_style=border))
    props = get_device_props()
    write_summary(outdir, outcomes, props)
    console.print(Panel(f"Reports saved to: {outdir}\nsummary.txt written.", border_style="green"))

# ───────────────────────────── Open reports folder ───────────────────────────

def open_reports_folder(accent: str) -> None:
    console.print(Panel(f"Reports folder: {REPORTS_DIR}", border_style=accent))
    xdg = which("xdg-open")
    if xdg:
        run_cmd([xdg, str(REPORTS_DIR)])

# ───────────────────────────── Auto-setup (non-destructive) ──────────────────

def ensure_mvt_portable(accent: str) -> None:
    if find_mvt_bin():
        return
    console.print(Panel("mvt-android not found. Attempting non-destructive setup…", border_style=accent))

    # 1) Try pipx (user-level, isolated)
    pipx = which("pipx")
    if pipx:
        run_cmd([pipx, "ensurepath"])
        rc, _ = run_cmd([pipx, "install", "mvt"])
        if find_mvt_bin():
            return

    # 2) Try pip --user (user-level site-packages)
    pip_sys = which("pip3") or which("pip")
    if pip_sys:
        rc, _ = run_cmd([pip_sys, "install", "--user", "mvt"])
        if find_mvt_bin():
            return

    # 3) Fallback: local venv inside app folder (portable)
    console.print(Panel("Setting up local virtual environment ./pgp-venv…", border_style=accent))
    run_cmd([sys.executable, "-m", "venv", str(VENV_DIR)])
    vb = venv_bin_dir()
    pip = vb / "pip"
    if _is_executable(pip):
        run_cmd([str(pip), "install", "--upgrade", "pip", "setuptools", "wheel"])
        run_cmd([str(pip), "install", "mvt"])
    if not find_mvt_bin():
        console.print(Panel(
            "Automatic setup couldn’t provide mvt-android.\n"
            "On Fedora Atomic/Bazzite, use Toolbox with Python 3.11:\n\n"
            "toolbox create --release f41\n"
            "toolbox enter\n"
            "sudo dnf install -y python3.11 python3.11-devel gcc make libusb1-devel android-tools\n"
            "python3.11 -m venv ~/pgp-venv && source ~/pgp-venv/bin/activate\n"
            "pip install --upgrade pip mvt\n",
            border_style="yellow"
        ))
        console.print(Panel(
            "If build fails with missing 'Python.h' or pyahocorasick wheels on Python 3.13, prefer Python 3.11 as above.",
            border_style="yellow"
        ))

def auto_setup(accent: str) -> None:
    console.print(Panel(f"📄 Log file: {LOG_FILE}", border_style=accent))
    # We rely on system adb now; provide instructions instead of downloading
    if not find_adb_bin():
        console.print(Panel(
            "ADB not found on PATH. Install it via your package manager:\n\n"
            "Linux:\n"
            "• Fedora/RHEL: sudo dnf install -y android-tools\n"
            "• Debian/Ubuntu: sudo apt install -y android-tools-adb\n"
            "• Arch: sudo pacman -S android-tools\n\n"
            "Windows:\n"
            "• winget: winget install --id Google.PlatformTools --source winget\n"
            "• Chocolatey: choco install adb\n"
            "• ZIP: https://dl.google.com/android/repository/platform-tools-latest-windows.zip (add to PATH)",
            border_style="yellow"
        ))
    ensure_mvt_portable(accent)

# ───────────────────────────── Menu (curses + fallback) ──────────────────────

MENU_ITEMS: List[Tuple[str, str]] = [
    ("Guided Setup", "wizard"),
    ("Manual / How-To", "manual"),
    ("Quick Checks", "checks"),
    ("Update IOCs", "update_iocs"),
    ("ADB Devices", "devices"),
    ("List MVT Modules", "modules"),
    ("Scan Android — All Modules", "scan_all"),
    ("Scan Android — Module by Module", "scan_by_module"),
    ("Open Reports Folder", "open_reports"),
    ("Delete All Data & Logs", "delete_all_data_logs"),
    ("About", "about"),
    ("Quit", "quit"),
]
def delete_all_data_and_logs(accent: str) -> None:
    import shutil
    deleted = []
    errors = []
    targets = [LOGS_DIR, REPORTS_DIR, DATA_HOME, MODULES_TXT]
    for t in targets:
        try:
            if t.exists():
                if t.is_dir():
                    shutil.rmtree(t)
                else:
                    t.unlink()
                deleted.append(str(t))
        except Exception as e:
            errors.append(f"{t}: {e}")
    msg = ""
    if deleted:
        msg += "Deleted:\n" + "\n".join(deleted) + "\n"
    if errors:
        msg += "Errors:\n" + "\n".join(errors)
    if not deleted and not errors:
        msg = "No data or logs found to delete."
    console.print(Panel(msg, title="Delete All Data & Logs", border_style=accent))

def menu_curses(accent: str) -> Optional[str]:
    if not (_HAVE_CURSES and sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    def _inner(stdscr):
        curses.curs_set(0)
        stdscr.nodelay(False)
        stdscr.keypad(True)
        idx = 0
        while True:
            stdscr.clear()
            h, w = stdscr.getmaxyx()
            title = f"{APP_SHORT} — Menu"
            hint = "↑/↓ select • Enter confirm • 1–9 hotkeys • q to quit"
            try: stdscr.addstr(1, max(0, (w - len(title)) // 2), title, curses.A_BOLD)
            except curses.error: pass
            for i, (label, _) in enumerate(MENU_ITEMS, 1):
                s = f"{i}. {label}"
                attr = curses.A_REVERSE if (i-1)==idx else curses.A_NORMAL
                try: stdscr.addstr(3+i, 4, s[:max(0, w-8)], attr)
                except curses.error: pass
            try: stdscr.addstr(h-2, 2, hint[:max(0, w-4)])
            except curses.error: pass
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (curses.KEY_UP, ord('k')):
                idx = (idx - 1) % len(MENU_ITEMS)
            elif ch in (curses.KEY_DOWN, ord('j')):
                idx = (idx + 1) % len(MENU_ITEMS)
            elif ch in (10, 13, curses.KEY_ENTER):
                return MENU_ITEMS[idx][1]
            elif ch in (27, ord('q')):
                return "quit"
            else:
                try:
                    d = int(chr(ch))
                    if 1 <= d <= len(MENU_ITEMS):
                        return MENU_ITEMS[d-1][1]
                except Exception:
                    pass
    try:
        return curses.wrapper(_inner)
    except Exception:
        return None

def menu_fallback(accent: str) -> Optional[str]:
    lines = [f" {i}. {label}" for i, (label, _) in enumerate(MENU_ITEMS, 1)]
    console.print(Panel("\n".join(lines), title=f"{APP_SHORT} — Menu (fallback)", border_style="yellow"))
    try:
        choice = input(f"Choose 1-{len(MENU_ITEMS)} (Enter to quit): ").strip()
    except EOFError:
        return "quit"
    if not choice:
        return "quit"
    if choice.isdigit():
        d = int(choice)
        if 1 <= d <= len(MENU_ITEMS):
            return MENU_ITEMS[d-1][1]
    return None

# ───────────────────────────── About / Manual / Header ───────────────────────

def banner_and_header(accent: str) -> None:
    banner(accent)
    console.print(Panel(
        "Created by Danijel Žalac (2025) • Special thanks: MVT, Amnesty International Security Lab\n"
        f"Repo: {REPO_URL}\nWiki: {WIKI_URL}\n"
        "What it does: runs indicative Android checks over ADB with up-to-date IOCs (MVT),\n"
        "summarizes results, and saves timestamped logs/reports locally.",
        border_style=accent))
    chips_line(header_known_sets(), accent)
    console.print(Rule(style=accent))
    console.print(Panel(f"📄 Log file: {LOG_FILE}", border_style=accent))

def manual_screen(accent: str) -> None:
    txt = Text()
    txt.append("Manual / How-To\n", style="bold")
    txt.append("\n")
    txt.append("1) Requirements\n", style="bold")
    txt.append("- Python 3.11 preferred (3.10–3.13 supported)\n")
    txt.append("- Android device + USB cable\n")
    txt.append("- ADB installed system-wide (adb on PATH)\n")
    txt.append("- MVT (Mobile Verification Toolkit). The app tries user-level installs first.\n\n")
    txt.append("Windows tips\n", style="bold")
    txt.append("   • Install adb: winget install --id Google.PlatformTools --source winget\n")
    txt.append("     or Chocolatey: choco install adb\n")
    txt.append("     or ZIP: download platform-tools and add to PATH\n\n")
    txt.append("2) Enable USB debugging on Android\n", style="bold")
    txt.append("   • Settings → About phone → tap “Build number” 7× to enable Developer options\n")
    txt.append("   • Settings → System → Developer options → enable “USB debugging”\n")
    txt.append("   • Connect phone via USB → choose File Transfer/MTP if prompted\n")
    txt.append("   • On first connect, accept the computer’s RSA fingerprint dialog on device\n\n")
    txt.append("3) Linux tips (permissions)\n", style="bold")
    txt.append("   • If `ADB Devices` shows none: unplug/replug USB, then:\n")
    txt.append("     - Run `adb kill-server && adb start-server` (menu → Quick Checks shows hints)\n")
    txt.append("     - Try another cable/port; ensure device is unlocked\n")
    txt.append("     - Some distros need udev rules for Android — consult your distro docs\n\n")
    txt.append("4) Bazzite / Fedora Atomic\n", style="bold")
    txt.append("   • Use Toolbox (no OS changes):\n")
    txt.append("     toolbox create --release f41\n")
    txt.append("     toolbox enter\n")
    txt.append("     sudo dnf install -y python3.11 python3.11-devel gcc make libusb1-devel android-tools\n")
    txt.append("     python3.11 -m venv ~/pgp-venv && source ~/pgp-venv/bin/activate\n")
    txt.append("     pip install --upgrade pip mvt\n\n")
    txt.append("5) First run flow\n", style="bold")
    txt.append("   • Manual / How-To (this screen) → Update IOCs → ADB Devices (confirm visibility)\n")
    txt.append("   • List MVT Modules → Scan (All Modules) or (Module by Module)\n")
    txt.append("   • Results: logs/PGP_*.log and reports/android_YYYYMMDD_HHMMSS/summary.txt\n\n")
    txt.append("6) Interpreting statuses\n", style="bold")
    txt.append("   • CLEAN (green): no indicators matched in parsed artifacts\n")
    txt.append("   • HITS (accent): at least one suspicious indicator matched → review hit types\n")
    txt.append("   • SKIPPED (yellow): module needs root/permission or artifact not present\n")
    txt.append("   • FAILED (red): tooling/ADB error; try ‘adb kill-server && adb start-server’\n\n")
    txt.append("7) Privacy & scope\n", style="bold")
    txt.append("   • This is an indicative check — not a full forensic guarantee\n")
    txt.append("   • Keep devices offline if you suspect compromise; review results before sharing\n\n")
    txt.append("Links\n", style="bold")
    txt.append(f"   • Repo: {REPO_URL}\n")
    txt.append(f"   • User Guide: {WIKI_URL}\n")
    console.print(Panel(txt, title="User Manual", border_style=accent, box=box.HEAVY))

def about_screen(accent: str, known_sets: List[str]) -> None:
    content = Text()
    content.append("Phone Guardian Pro — Professional CLI\n", style="bold")
    content.append("Created by Danijel Žalac (2025) • Special thanks: MVT, Amnesty International Security Lab\n")
    content.append(f"\nRepo: {REPO_URL}\nWiki: {WIKI_URL}\n")
    content.append("\nKnown spyware sets (from installed IOCs):\n")
    for s in known_sets:
        content.append(f" • {s}\n")
    content.append("\nWhat it does:\nRuns indicative Android checks over ADB with up-to-date IOCs via MVT, summarizes, and stores logs/reports locally.\n")
    console.print(Panel(content, title="About", border_style=accent, box=box.HEAVY))

# ───────────────────────────── CLI entry & actions ───────────────────────────

def do_action(choice: str, accent: str, hit_mode: str) -> None:
    if choice == "manual":
        manual_screen(accent)
    elif choice == "wizard":
        guided_setup_wizard(accent)
    elif choice == "checks":
        quick_checks_ui(accent)
    elif choice == "update_iocs":
        mvt_download_iocs_ui(accent)
    elif choice == "devices":
        adb_devices_table(accent)
    elif choice == "modules":
        list_modules_ui(accent)
    elif choice == "scan_all":
        scan_all_modules(accent, hit_mode)
    elif choice == "scan_by_module":
        scan_module_by_module(accent, hit_mode)
    elif choice == "open_reports":
        open_reports_folder(accent)
    elif choice == "delete_all_data_logs":
        delete_all_data_and_logs(accent)
    elif choice == "about":
        known = [friendly_ioc_name(p) for p in list_installed_iocs()] or header_known_sets(12)
        about_screen(accent, known)
    else:
        console.print(Panel("Unknown action.", border_style="red"))

# ───────────────────────────── Self-test ─────────────────────────────────────

def selftest() -> int:
    failures: List[str] = []

    # Parse mocked help banner
    sample_help = "Mobile Verification Toolkit — Android\nUsage: ...\nVersion: 2.7.1\n..."
    if parse_mvt_version(sample_help) != "2.7.1":
        failures.append("parse mvt version")

    # Parse sample --list-modules output
    sample_list = "- ChromeHistory\n- Dumpsys\n- Packages\n- Processes\n"
    mods: List[str] = []
    for line in sample_list.splitlines():
        m = re.search(r"-\s+([A-Za-z0-9_]+)\s*$", line)
        if m:
            mods.append(m.group(1))
    if mods != ["ChromeHistory", "Dumpsys", "Packages", "Processes"]:
        failures.append("parse modules")

    # Error mapping
    status, reason = classify_stdout("Error: Device is busy. Try again.")
    if status != "FAILED" or "kill-server" not in (reason or ""):
        failures.append("device busy mapping")
    status, reason = classify_stdout("permission denied for history db")
    if status != "SKIPPED":
        failures.append("permission mapping")

    # Compile this file (string literals)
    try:
        code = Path(__file__).read_text(encoding="utf-8")
        compile(code, __file__, "exec")
    except Exception as e:
        failures.append(f"self-compile: {e}")

    if failures:
        console.print(Panel("SELFTEST FAIL:\n" + "\n".join(f"- {f}" for f in failures), border_style="red"))
        return 1
    console.print(Panel("SELFTEST OK", border_style="green"))
    return 0

# ───────────────────────────── Argparse / Main loop ──────────────────────────

def parse_args(argv: Optional[Sequence[str]] = None):
    ap = argparse.ArgumentParser(
        prog="PhoneGuardianPro.py",
        description="Phone Guardian Pro — MVT-based indicative Android checks over ADB",
        add_help=True,
    )
    ap.add_argument("--accent", choices=list(ACCENTS.keys()), default=DEFAULT_ACCENT, help="accent color: teal|blue|purple")
    ap.add_argument("--hit-types", choices=list(HIT_TYPES), default="min", help="detail level when HITS occur: none|min|all")
    ap.add_argument("command", nargs="?", choices=[
        "wizard","manual","checks","update-iocs","devices","modules","scan-all","scan-by-module","open-reports","about",
    ], help="optional direct command")
    return ap.parse_args(argv)

def interactive_loop(accent: str, hit_mode: str) -> None:
    # Optional curses menu
    def menu_curses(accent: str) -> Optional[str]:
        if not (_HAVE_CURSES and sys.stdin.isatty() and sys.stdout.isatty()):
            return None
        def _inner(stdscr):
            curses.curs_set(0); stdscr.nodelay(False); stdscr.keypad(True)
            idx = 0
            while True:
                stdscr.clear()
                h, w = stdscr.getmaxyx()
                title = f"{APP_SHORT} — Menu"
                hint = "↑/↓ select • Enter confirm • 1–9 hotkeys • q to quit"
                try: stdscr.addstr(1, max(0, (w - len(title)) // 2), title, curses.A_BOLD)
                except curses.error: pass
                for i, (label, _) in enumerate(MENU_ITEMS, 1):
                    s = f"{i}. {label}"
                    attr = curses.A_REVERSE if (i-1)==idx else curses.A_NORMAL
                    try: stdscr.addstr(3+i, 4, s[:max(0, w-8)], attr)
                    except curses.error: pass
                try: stdscr.addstr(h-2, 2, hint[:max(0, w-4)])
                except curses.error: pass
                stdscr.refresh()
                ch = stdscr.getch()
                if ch in (curses.KEY_UP, ord('k')):   idx = (idx - 1) % len(MENU_ITEMS)
                elif ch in (curses.KEY_DOWN, ord('j')): idx = (idx + 1) % len(MENU_ITEMS)
                elif ch in (10, 13, curses.KEY_ENTER):  return MENU_ITEMS[idx][1]
                elif ch in (27, ord('q')):               return "quit"
                else:
                    try:
                        d = int(chr(ch))
                        if 1 <= d <= len(MENU_ITEMS):
                            return MENU_ITEMS[d-1][1]
                    except Exception:
                        pass
        try:
            return curses.wrapper(_inner)
        except Exception:
            return None

    while True:
        console.clear()
        banner_and_header(accent)
        choice = menu_curses(accent)
        if not choice:
            # Fallback numeric menu
            lines = [f" {i}. {label}" for i, (label, _) in enumerate(MENU_ITEMS, 1)]
            console.print(Panel("\n".join(lines), title=f"{APP_SHORT} — Menu (fallback)", border_style="yellow"))
            try:
                raw = input(f"Choose 1-{len(MENU_ITEMS)} (Enter to quit): ").strip()
            except EOFError:
                choice = "quit"
            else:
                if not raw:
                    choice = "quit"
                elif raw.isdigit() and 1 <= int(raw) <= len(MENU_ITEMS):
                    choice = MENU_ITEMS[int(raw)-1][1]
                else:
                    continue
        if choice == "quit":
            console.print(Panel("Goodbye.", border_style=accent))
            break
        console.clear()
        banner_and_header(accent)
        do_action(choice, accent, hit_mode)
        console.print()
        console.print("[dim]Press ENTER to return to menu…[/]")
        try: input()
        except EOFError: break

def main() -> int:
    if os.environ.get("PGP_SELFTEST") == "1":
        return selftest()

    args_ns = parse_args()
    accent = ACCENTS.get(args_ns.accent, ACCENTS[DEFAULT_ACCENT])
    hit_mode = args_ns.hit_types

    console.clear()
    # Non-interactive single command mode
    if args_ns.command:
        # Normalize hyphenated CLI commands to internal underscore action keys
        normalized_cmd = args_ns.command.replace("-", "_")
        banner_and_header(accent)
        console.print(Panel("Auto-setup (non-destructive)…", border_style=accent))
        auto_setup(accent)
        do_action(normalized_cmd, accent, hit_mode)
        return 0

    # Interactive
    banner_and_header(accent)
    console.print(Panel("Auto-setup (non-destructive)…", border_style=accent))
    auto_setup(accent)
    interactive_loop(accent, hit_mode)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        try:
            _LOG_FH.close()
        except Exception:
            pass
