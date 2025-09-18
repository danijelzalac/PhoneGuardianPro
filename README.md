# Phone Guardian Pro

Professional CLI for indicative Android checks using MVT.

## Features
- Runs MVT Android checks over ADB
- Summarizes results, logs, and reports
- Minimal dependencies (Rich, optional curses)

## Usage
- Requires Python 3.10–3.13 (3.11 preferred)
- Install dependencies: `pip install rich`
- Run: `python PhoneGuardianPro.py`

## Creating a Windows .exe
1. Install PyInstaller: `pip install pyinstaller`
2. Run: `pyinstaller --onefile --name "PhoneGuardianPro" PhoneGuardianPro.py`
3. The .exe will be in the `dist/` folder

## License
See LICENSE file.

## Links
- [Project repo](https://github.com/danijelzalac/PhoneGuardianPro)
- [User Guide](https://github.com/danijelzalac/PhoneGuardianPro/wiki/HomePhoneGuardianPro-%E2%80%93-User-Guide)
