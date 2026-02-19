# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\willi\\OneDrive\\Test\\K\\Testing_Code\\ransomware_simulator.py'],
    pathex=['C:\\Users\\willi\\OneDrive\\Test\\K\\testing_code\\dynamic_path_config'],
    binaries=[],
    datas=[],
    hiddenimports=['path_config'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='RansomwareSimulator',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
