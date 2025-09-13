# portable_mvt_gui_mvt_only.py
"""
PhoneGuardianPro – MVT-only GUI (PyQt5 preferred)
Created by Danijel Zalac 2005 • Special thanks to the MVT project & Amnesty Security Lab

Šta radi ova verzija (samo MVT):
• List ADB devices (koristi vaš adb.exe – birate ga dugmetom)
• Pokretanje MVT "check-adb" sa live logom
• "Update IOCs" (preuzimanje indikatora) sa live logom
• Biranje putanja (adb.exe, MVT alat) preko dijaloga – bez kucanja
• Čuvanje podešavanja u pgp_settings.json
• Crvena traka za upozorenja (kompaktna), veliki terminal za napredak
• Dugme Stop sa bezbednim gašenjem procesa (i forsiranim kill-om ako zapne)
• Kratak rezime nalaza (Warnings/Criticals) po završetku

Napomena o MVT izvoru: ako nemate mvt-android.exe, ali imate repozitorijum „MVT/“ (kao kod vas),
program će automatski pokrenuti „python -m mvt.android.cli …“ i dodaće „MVT/src“ u PYTHONPATH,
pa nema potrebe za instalacijom preko pip-a.
"""
import os
import re
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(BASE_DIR, 'pgp_settings.json')

# ------------------------------------------------------------
# Omogući "portable" PyQt5 (dodaj lokalni site-packages u sys.path i Qt bin u PATH)
# ------------------------------------------------------------
LOCAL_SITE = os.path.join(BASE_DIR, 'python', 'Lib', 'site-packages')
if os.path.isdir(LOCAL_SITE) and LOCAL_SITE not in sys.path:
    sys.path.insert(0, LOCAL_SITE)
# Dodaj Qt bin u PATH (potrebno na Windows-u da bi se učitale Qt DLL-ovi)
qt_bin = os.path.join(LOCAL_SITE, 'PyQt5', 'Qt5', 'bin')
if os.path.isdir(qt_bin):
    os.environ['PATH'] = qt_bin + os.pathsep + os.environ.get('PATH', '')

# Pokušaj PyQt5 (preferirano). Ako ne uspe – Tk fallback.
USE_QT = False
try:
    from PyQt5 import QtCore, QtGui, QtWidgets  # type: ignore
    USE_QT = True
except Exception:
    USE_QT = False

# Podrazumevane putanje (mogu se promeniti iz aplikacije)
DEFAULT_ADB = os.path.join(BASE_DIR, 'adb', 'adb.exe') if sys.platform.startswith('win') else 'adb'
DEFAULT_MVT_EXE = os.path.join(BASE_DIR, 'python', 'Scripts', 'mvt-android.exe') if sys.platform.startswith('win') else 'mvt-android'
MVT_SRC_DIR = os.path.join(BASE_DIR, 'MVT', 'src')  # za PYTHONPATH kad pokrećemo -m mvt.android.cli

CRITICAL_KEYWORDS = ['critical', 'found', 'infected', 'indicator', 'suspicious', 'malware', 'warning']

# ---------------- Zajedničke pomoćne funkcije ----------------
def ts() -> str:
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def write_log_file(line: str) -> None:
    with open(os.path.join(LOG_DIR, 'latest.log'), 'a', encoding='utf-8') as f:
        f.write(f"[{ts()}] {line}\n")

# ==================================================================================
#                                         PyQt5
# ==================================================================================
if USE_QT:
    class ProcessRunner(QtCore.QObject):
        line = QtCore.pyqtSignal(str)
        finished = QtCore.pyqtSignal(int)
        started = QtCore.pyqtSignal()
        error = QtCore.pyqtSignal(str)

        def __init__(self, parent=None):
            super().__init__(parent)
            self.proc: QtCore.QProcess | None = None

        def start(self, cmd, cwd=None, extra_env: dict | None = None):
            if self.proc is not None:
                self.error.emit('Process already running')
                return
            self.proc = QtCore.QProcess(self)
            if cwd:
                self.proc.setWorkingDirectory(cwd)
            env = self.proc.processEnvironment()
            if extra_env:
                for k, v in extra_env.items():
                    env.insert(k, v)
            env.insert('PYTHONIOENCODING', 'utf-8')
            self.proc.setProcessEnvironment(env)

            self.proc.readyReadStandardOutput.connect(self._read_stdout)
            self.proc.readyReadStandardError.connect(self._read_stderr)
            self.proc.started.connect(lambda: self.started.emit())
            self.proc.finished.connect(self._on_finished)
            try:
                if isinstance(cmd, (list, tuple)):
                    program, args = cmd[0], cmd[1:]
                    self.proc.start(program, args)
                else:
                    self.proc.start(cmd)
            except Exception as e:
                self.error.emit(str(e))
                self.proc = None

        def _read_stdout(self):
            if not self.proc:
                return
            data = self.proc.readAllStandardOutput()
            text = bytes(data).decode('utf-8', errors='replace')
            for line in text.splitlines():
                self.line.emit(line)

        def _read_stderr(self):
            if not self.proc:
                return
            data = self.proc.readAllStandardError()
            text = bytes(data).decode('utf-8', errors='replace')
            for line in text.splitlines():
                self.line.emit(line)

        def _on_finished(self, exit_code, _status=None):
            try:
                self.finished.emit(int(exit_code))
            finally:
                self.proc = None

        def kill(self):
            if self.proc and self.proc.state() != QtCore.QProcess.NotRunning:
                self.proc.kill()

    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle('PhoneGuardianPro – MVT')
            self.resize(1100, 750)
            self.settings = self._load_settings()
            self.current_runner: ProcessRunner | None = None
            self.findings = {'warnings': 0, 'criticals': 0}
            self._stopping = False

            self._build_ui()
            self._connect()

            # automatski popis uređaja nakon starta
            QtCore.QTimer.singleShot(300, self.list_devices)

        # ---------------- Settings ----------------
        def _load_settings(self):
            s = {
                'adb_path': DEFAULT_ADB,
                'mvt_path': DEFAULT_MVT_EXE,
            }
            try:
                if os.path.exists(SETTINGS_FILE):
                    with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for k in ('adb_path', 'mvt_path'):
                            if k in data:
                                s[k] = data[k]
            except Exception:
                pass
            return s

        def _save_settings(self):
            try:
                with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(self.settings, f, indent=2)
                self._log('Settings saved.')
            except Exception as e:
                self._log(f'Error saving settings: {e}', 'ERROR')

        # ---------------- UI ----------------
        def _build_ui(self):
            central = QtWidgets.QWidget()
            self.setCentralWidget(central)
            v = QtWidgets.QVBoxLayout(central)

            # Gornja traka – kontrole
            top = QtWidgets.QHBoxLayout()
            self.btn_list = QtWidgets.QPushButton('List Devices')
            self.btn_check = QtWidgets.QPushButton('Check ADB (MVT)')
            self.btn_iocs = QtWidgets.QPushButton('Update IOCs')
            self.btn_stop = QtWidgets.QPushButton('Stop')
            self.btn_stop.setEnabled(False)
            top.addWidget(self.btn_list)
            top.addWidget(self.btn_check)
            top.addWidget(self.btn_iocs)
            top.addStretch()
            top.addWidget(self.btn_stop)
            v.addLayout(top)

            # Red sa putanjama (dva dugmeta za biranje)
            paths = QtWidgets.QHBoxLayout()
            self.lbl_adb = QtWidgets.QLabel(self.settings.get('adb_path', ''))
            self.lbl_mvt = QtWidgets.QLabel(self.settings.get('mvt_path', ''))
            self.btn_pick_adb = QtWidgets.QPushButton('Select ADB…')
            self.btn_pick_mvt = QtWidgets.QPushButton('Select MVT Tool…')
            paths.addWidget(self.btn_pick_adb)
            paths.addWidget(self.lbl_adb)
            paths.addSpacing(20)
            paths.addWidget(self.btn_pick_mvt)
            paths.addWidget(self.lbl_mvt)
            paths.addStretch()
            v.addLayout(paths)

            # Splitter: veliki log
            splitter = QtWidgets.QSplitter()
            v.addWidget(splitter)

            left = QtWidgets.QWidget()
            left_l = QtWidgets.QVBoxLayout(left)
            self.log = QtWidgets.QTextEdit()
            self.log.setReadOnly(True)
            self.log.setFont(QtGui.QFont('Consolas', 10))
            left_l.addWidget(self.log)

            status_row = QtWidgets.QHBoxLayout()
            self.status = QtWidgets.QLabel('Ready')
            self.pb = QtWidgets.QProgressBar()
            self.pb.setRange(0, 0)
            self.pb.hide()
            status_row.addWidget(self.status)
            status_row.addStretch()
            status_row.addWidget(self.pb)
            left_l.addLayout(status_row)

            splitter.addWidget(left)
            splitter.setSizes([900])

            # Help box – koristi trostruke navodnike da nema sintaks grešaka
            help_box = QtWidgets.QGroupBox('How-to & Notes')
            help_l = QtWidgets.QVBoxLayout(help_box)
            help_text = QtWidgets.QLabel(
                """
• Connect Android device with USB debugging enabled and unlocked.
• List Devices → to detect ADB devices.
• Check ADB (MVT) → runs mvt check-adb with live logs.
• Update IOCs → downloads the latest indicators.
• Use Select… buttons to pick adb.exe and MVT tool without typing.
                """.strip()
            )
            help_text.setWordWrap(True)
            help_l.addWidget(help_text)
            v.addWidget(help_box)

            # Kompaktna crvena traka (upozorenja)
            self.banner = QtWidgets.QLabel('')
            self.banner.setAlignment(QtCore.Qt.AlignCenter)
            self.banner.setStyleSheet('background:#a90000; color:#fff; padding:6px; font-weight:bold;')
            self.banner.hide()
            v.addWidget(self.banner)

            # Footer kredit
            credit = QtWidgets.QLabel('Created by Danijel Zalac 2005 • Special thanks to the MVT project & Amnesty Security Lab')
            credit.setAlignment(QtCore.Qt.AlignCenter)
            credit.setStyleSheet('color:#bbb; padding:6px;')
            v.addWidget(credit)

            # Tamna tema
            self._apply_dark_theme()

        def _apply_dark_theme(self):
            self.setStyleSheet('''
                QWidget { color: #fff; }
                QMainWindow { background: #2c2f38; }
                QTextEdit { background:#1e1e1e; color:#fff; }
                QPushButton { background:#3c3f51; color:#fff; padding:6px 10px; }
                QPushButton:disabled { background:#2d2f3a; color:#aaa; }
                QGroupBox { border:1px solid #444; margin-top:8px; }
                QGroupBox::title { subcontrol-origin: margin; left: 8px; padding:0 4px; }
                QProgressBar { background:#1e1e1e; border:1px solid #555; text-align:center; }
            ''')

        def _connect(self):
            self.btn_list.clicked.connect(self.list_devices)
            self.btn_check.clicked.connect(self.run_check_adb)
            self.btn_iocs.clicked.connect(self.run_download_iocs)
            self.btn_pick_adb.clicked.connect(self.pick_adb)
            self.btn_pick_mvt.clicked.connect(self.pick_mvt)
            self.btn_stop.clicked.connect(self.stop_current)

        # ---------------- Logovanje i upozorenja ----------------
        def _log(self, text: str, level: str = 'INFO'):
            cursor = self.log.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)
            fmt = QtGui.QTextCharFormat()
            color = {'ERROR': 'red', 'WARN': 'orange', 'INFO': 'lightgreen'}.get(level, 'white')
            fmt.setForeground(QtGui.QBrush(QtGui.QColor(color)))
            cursor.insertText(f'[{ts()}] {text}\n', fmt)
            self.log.ensureCursorVisible()
            write_log_file(text)
            self._track_findings(text)

        def _track_findings(self, text: str):
            low = text.lower()
            if any(k in low for k in ('critical', 'malware', 'infected')):
                self.findings['criticals'] += 1
                self._show_banner('Important: findings reported — check logs')
            elif any(k in low for k in ('warning', 'indicator', 'suspicious')):
                self.findings['warnings'] += 1
                self._show_banner('Important: findings reported — check logs')

        def _show_banner(self, text: str):
            self.banner.setText(text)
            self.banner.show()

        def _hide_banner(self):
            self.banner.hide()

        def _set_busy(self, busy: bool, label: str | None = None):
            for w in (self.btn_list, self.btn_check, self.btn_iocs, self.btn_pick_adb, self.btn_pick_mvt):
                w.setEnabled(not busy)
            self.btn_stop.setEnabled(busy and not self._stopping)
            if busy:
                if label:
                    self.status.setText(label)
                self.pb.show()
            else:
                self.status.setText('Ready')
                self.pb.hide()

        def _reset_findings(self):
            self.findings = {'warnings': 0, 'criticals': 0}
            self._hide_banner()

        # ---------------- Biranje putanja ----------------
        def pick_adb(self):
            start = os.path.dirname(self.settings.get('adb_path') or DEFAULT_ADB)
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Select adb.exe', start, 'adb.exe (adb.exe);;All Files (*)')
            if path:
                self.settings['adb_path'] = path
                self.lbl_adb.setText(path)
                self._save_settings()

        def pick_mvt(self):
            start = os.path.dirname(self.settings.get('mvt_path') or DEFAULT_MVT_EXE)
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Select mvt-android.exe OR python.exe', start, 'Executables (*.exe);;All Files (*)')
            if path:
                self.settings['mvt_path'] = path
                self.lbl_mvt.setText(path)
                self._save_settings()

        # ---------------- Kreiranje komandi i okruženja ----------------
        def _adb_path(self) -> str:
            return self.settings.get('adb_path') or DEFAULT_ADB

        def _is_mvt_exe(self, p: str) -> bool:
            base = os.path.basename(p).lower()
            return 'mvt-android' in base

        def _mvt_cmd(self, subcmd: str):
            """Vrati komandu kao listu.
            Ako je odabran mvt-android.exe → [mvt-android.exe, subcmd]
            Inače koristi Python interpreter → [python, -m, mvt.android.cli, subcmd]
            """
            sel = self.settings.get('mvt_path') or DEFAULT_MVT_EXE
            if os.path.isfile(sel) and self._is_mvt_exe(sel):
                return [sel, subcmd], False  # False ⇒ ne treba PYTHONPATH
            # python putanja – koristi baš ovaj interpreter
            py = sel if os.path.basename(sel).lower().startswith('python') else sys.executable
            return [py, '-m', 'mvt.android.cli', subcmd], True  # True ⇒ koristi MVT/src

        def _extra_env(self, needs_mvt_src: bool) -> dict:
            env = {}
            # ADB dir -> PATH
            adb_dir = os.path.dirname(self._adb_path())
            current = os.environ.get('PATH', '')
            env['PATH'] = (adb_dir + os.pathsep + current) if adb_dir else current
            env['PYTHONIOENCODING'] = 'utf-8'
            # Ako pokrećemo -m mvt.android.cli, dodaj MVT/src u PYTHONPATH
            if needs_mvt_src and os.path.isdir(MVT_SRC_DIR):
                existing = os.environ.get('PYTHONPATH', '')
                env['PYTHONPATH'] = MVT_SRC_DIR + (os.pathsep + existing if existing else '')
            return env

        def _start_proc(self, cmd, title: str, needs_mvt_src_env: bool, on_line=None, on_finish=None):
            if self.current_runner:
                self._log('A process is already running. Use Stop to cancel or wait it to finish.', 'WARN')
                return
            self._reset_findings()
            self._stopping = False
            self.current_runner = ProcessRunner(self)
            if on_line:
                self.current_runner.line.connect(lambda s: on_line(s))
            else:
                self.current_runner.line.connect(lambda s: self._log(s))
            self.current_runner.error.connect(lambda e: self._log(e, 'ERROR'))

            def _done(code):
                self._log(f'--- {title} finished (exit {code}) ---', 'INFO' if code == 0 else 'ERROR')
                self._set_busy(False)
                self.btn_stop.setEnabled(False)
                self._stopping = False
                self.current_runner = None
                if self.findings['warnings'] or self.findings['criticals']:
                    QtWidgets.QMessageBox.warning(
                        self,
                        'Scan Summary',
                        f"Warnings: {self.findings['warnings']}\nCriticals: {self.findings['criticals']}\n\nOpen the log above for details."
                    )
                if on_finish:
                    try:
                        on_finish(code)
                    except Exception as e:
                        self._log(f'On-finish handler error: {e}', 'ERROR')

            self.current_runner.finished.connect(_done)
            self._set_busy(True, title)
            self._log(f'{title} started…')
            self.current_runner.start(cmd, cwd=BASE_DIR, extra_env=self._extra_env(needs_mvt_src_env))

        def stop_current(self):
            if self._stopping:
                self._log('Already stopping…', 'WARN')
                return
            if not self.current_runner or not self.current_runner.proc:
                self._log('No process is running.', 'WARN')
                return
            self._stopping = True
            self.btn_stop.setEnabled(False)
            self._log('Stopping current process…', 'WARN')
            p = self.current_runner.proc
            try:
                p.terminate()
                QtCore.QTimer.singleShot(1500, lambda: self._force_kill_if_running(p))
            except Exception as e:
                self._log(f'Failed to stop: {e}', 'ERROR')

        def _force_kill_if_running(self, p: QtCore.QProcess):
            if p.state() == QtCore.QProcess.NotRunning:
                return
            self._log('Force killing process…', 'WARN')
            try:
                pid = int(p.processId()) if hasattr(p, 'processId') else None
            except Exception:
                pid = None
            try:
                p.kill()
            except Exception as e:
                self._log(f'Kill failed: {e}', 'ERROR')
            if sys.platform.startswith('win') and pid:
                try:
                    subprocess.run(['taskkill', '/PID', str(pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception as e:
                    self._log(f'taskkill failed: {e}', 'ERROR')

        # ---------------- Akcije ----------------
        def list_devices(self):
            adb = self._adb_path()
            if not adb:
                self._log('ADB path is not set.', 'ERROR')
                return
            self._start_proc([adb, 'devices', '-l'], 'List devices', False, on_line=self._on_list_line, on_finish=self._on_list_done)

        def _on_list_line(self, line: str):
            if line.strip().startswith('List of devices attached'):
                return
            self._log(line)

        def _on_list_done(self, code: int):
            if code == 0:
                self._log('ADB: list completed.')
            else:
                self._log('ADB: list finished with errors.', 'ERROR')

        def _restart_adb(self):
            try:
                adb = self._adb_path()
                subprocess.run([adb, 'kill-server'], cwd=BASE_DIR, check=False)
                subprocess.run([adb, 'start-server'], cwd=BASE_DIR, check=False)
                self._log('ADB server restarted.')
            except Exception as e:
                self._log(f'ADB restart failed: {e}', 'ERROR')

        def run_check_adb(self):
            cmd, needs_src = self._mvt_cmd('check-adb')
            self._start_proc(cmd, 'MVT check-adb', needs_src, on_line=self._on_mvt_line, on_finish=self._on_mvt_done)

        def run_download_iocs(self):
            cmd, needs_src = self._mvt_cmd('download-iocs')
            self._start_proc(cmd, 'MVT download-iocs', needs_src, on_line=self._on_mvt_line, on_finish=self._on_mvt_done)

        def _on_mvt_line(self, line: str):
            self._log(line)
            if 'device is busy' in line.lower():
                self._log('Device busy reported by MVT; trying to restart ADB…', 'WARN')
                self._restart_adb()

        def _on_mvt_done(self, code: int):
            if code == 0:
                self._log('MVT finished successfully.')
            else:
                self._log('MVT finished with errors. Review the log above.', 'ERROR')

        # ---------------- Zatvaranje ----------------
        def closeEvent(self, event):
            if self.current_runner and self.current_runner.proc:
                try:
                    self.current_runner.kill()
                except Exception:
                    pass
            self._save_settings()
            event.accept()

    def main_qt():
        app = QtWidgets.QApplication(sys.argv)
        app.setStyle('Fusion')
        pal = QtGui.QPalette()
        pal.setColor(QtGui.QPalette.Window, QtGui.QColor('#2c2f38'))
        pal.setColor(QtGui.QPalette.WindowText, QtGui.QColor('white'))
        pal.setColor(QtGui.QPalette.Base, QtGui.QColor('#1e1e1e'))
        pal.setColor(QtGui.QPalette.Text, QtGui.QColor('white'))
        pal.setColor(QtGui.QPalette.Button, QtGui.QColor('#3c3f51'))
        pal.setColor(QtGui.QPalette.ButtonText, QtGui.QColor('white'))
        app.setPalette(pal)

        win = MainWindow()
        win.show()
        write_log_file('App started using PyQt5 (MVT-only).')
        sys.exit(app.exec_())

# ==================================================================================
#                                       Tk Fallback
# ==================================================================================
if not USE_QT:
    import tkinter as tk
    from tkinter import ttk, filedialog

    class TkApp:
        def __init__(self):
            self.root = tk.Tk()
            self.root.title('PhoneGuardianPro – MVT (Tk Fallback)')
            self.root.geometry('1100x750')

            self.banner = tk.Label(self.root, text='', bg='#a90000', fg='white', font=('Arial', 10, 'bold'))
            self.banner.pack(fill='x')
            self.banner.pack_forget()

            frm = tk.Frame(self.root)
            frm.pack(fill='both', expand=True)
            self.text = tk.Text(frm, bg='#1e1e1e', fg='white', insertbackground='white', font=('Consolas', 10))
            self.text.pack(side='left', fill='both', expand=True)
            sb = ttk.Scrollbar(frm, command=self.text.yview)
            sb.pack(side='right', fill='y')
            self.text['yscrollcommand'] = sb.set

            self.pb = ttk.Progressbar(self.root, mode='indeterminate')
            self.pb.pack(fill='x')

            row = tk.Frame(self.root)
            row.pack(fill='x')
            tk.Button(row, text='Select ADB…', command=self.pick_adb).pack(side='left', padx=5, pady=5)
            tk.Button(row, text='Select MVT Tool…', command=self.pick_mvt).pack(side='left', padx=5, pady=5)
            tk.Button(row, text='List Devices', command=self.list_devices).pack(side='left', padx=5, pady=5)
            tk.Button(row, text='Check ADB (MVT)', command=self.run_check_adb).pack(side='left', padx=5, pady=5)
            tk.Button(row, text='Update IOCs', command=self.run_download_iocs).pack(side='left', padx=5, pady=5)

            self.status = tk.Label(self.root, text='Ready', fg='white', bg='#2c2f38')
            self.status.pack(fill='x')

            self.settings = {
                'adb_path': DEFAULT_ADB,
                'mvt_path': DEFAULT_MVT_EXE,
            }
            try:
                if os.path.exists(SETTINGS_FILE):
                    with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                        self.settings.update(json.load(f))
            except Exception:
                pass

            self.log('[OK]   Tk fallback loaded (install PyQt5 for full UI).')

        def log(self, msg: str, level: str = 'INFO'):
            self.text.insert('end', f'[{ts()}] {msg}\n')
            self.text.see('end')
            write_log_file(msg)
            if any(kw in msg.lower() for kw in CRITICAL_KEYWORDS):
                self.banner.config(text='Important: findings reported — check logs')
                self.banner.pack(fill='x')

        def pick_adb(self):
            path = filedialog.askopenfilename(title='Select adb.exe', filetypes=[('adb.exe', 'adb.exe'), ('All files', '*.*')])
            if path:
                self.settings['adb_path'] = path
                self.save_settings()
                self.log(f'ADB set to: {path}')

        def pick_mvt(self):
            path = filedialog.askopenfilename(title='Select mvt-android.exe OR python.exe', filetypes=[('Executables', '*.exe'), ('All files', '*.*')])
            if path:
                self.settings['mvt_path'] = path
                self.save_settings()
                self.log(f'MVT tool set to: {path}')

        def save_settings(self):
            try:
                with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(self.settings, f, indent=2)
                self.log('Settings saved.')
            except Exception as e:
                self.log(f'Error saving settings: {e}', 'ERROR')

        def _extra_env(self, needs_src: bool) -> dict:
            env = os.environ.copy()
            adb_dir = os.path.dirname(self.settings.get('adb_path') or DEFAULT_ADB)
            env['PATH'] = adb_dir + os.pathsep + env.get('PATH', '')
            env['PYTHONIOENCODING'] = 'utf-8'
            if needs_src and os.path.isdir(MVT_SRC_DIR):
                env['PYTHONPATH'] = MVT_SRC_DIR + os.pathsep + env.get('PYTHONPATH', '')
            return env

        def _mvt_cmd(self, subcmd: str):
            sel = self.settings.get('mvt_path') or DEFAULT_MVT_EXE
            if os.path.isfile(sel) and ('mvt-android' in os.path.basename(sel).lower()):
                return [sel, subcmd], False
            py = sel if os.path.basename(sel).lower().startswith('python') else sys.executable
            return [py, '-m', 'mvt.android.cli', subcmd], True

        def list_devices(self):
            adb = self.settings.get('adb_path') or DEFAULT_ADB
            try:
                out = subprocess.run([adb, 'devices', '-l'], cwd=BASE_DIR, env=self._extra_env(False), capture_output=True, text=True, errors='replace')
                self.log(out.stdout.strip() or '(no output)')
                if out.returncode != 0:
                    self.log(out.stderr.strip(), 'ERROR')
            except Exception as e:
                self.log(f'ADB error: {e}', 'ERROR')

        def run_check_adb(self):
            try:
                cmd, needs_src = self._mvt_cmd('check-adb')
                out = subprocess.run(cmd, cwd=BASE_DIR, env=self._extra_env(needs_src), capture_output=True, text=True, errors='replace')
                self.log(out.stdout.strip() or '(no output)')
                if out.returncode != 0:
                    self.log(out.stderr.strip(), 'ERROR')
            except Exception as e:
                self.log(f'MVT error: {e}', 'ERROR')

        def run_download_iocs(self):
            try:
                cmd, needs_src = self._mvt_cmd('download-iocs')
                out = subprocess.run(cmd, cwd=BASE_DIR, env=self._extra_env(needs_src), capture_output=True, text=True, errors='replace')
                self.log(out.stdout.strip() or '(no output)')
                if out.returncode != 0:
                    self.log(out.stderr.strip(), 'ERROR')
            except Exception as e:
                self.log(f'MVT error: {e}', 'ERROR')

        def run(self):
            write_log_file('App started using Tkinter fallback (MVT-only).')
            self.root.mainloop()

    def main_tk():
        TkApp().run()

# ---------------- Main ----------------
if __name__ == '__main__':
    if USE_QT:
        main_qt()
    else:
        main_tk()

# Footer
write_log_file('Created by Danijel Zalac 2005 • Special thanks to the MVT project & Amnesty Security Lab')
