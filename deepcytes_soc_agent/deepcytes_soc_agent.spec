# -*- mode: python ; coding: utf-8 -*-
import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

current_dir = os.path.abspath('.')
parent_dir = os.path.dirname(current_dir)

hiddenimports = (
    collect_submodules('mitmproxy') +
    collect_submodules('scapy') +
    collect_submodules('uvicorn') +
    collect_submodules('fastapi') +
    collect_submodules('pydantic') +
    collect_submodules('kafka') +
    [
        'win32evtlog',
        'win32con',
        'win32api',
        'win32security',
        'psutil',
        'yaml',
        'rich',
        'rich.console',
        'rich.table',
        'rich.panel',
        'rich.columns',
        'agents',
        'alerts',
        'analytics',
        'api',
        'collectors',
        'config',
        'core',
        'detectors',
        'event_engine',
        'integrations',
        'kafka',
        'monitoring',
        'plugins',
        'scheduler',
        'storage',
        'utils',
    ]
)

config_path = os.path.join(parent_dir, 'config.yaml')
datas = [
    (config_path, '.'),
    ('collectors/http_addon.py', 'collectors'),
] + collect_data_files('mitmproxy')

a = Analysis(
    ['main.py'],
    pathex=[current_dir, parent_dir],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='DeepCytes_SOC_Agent',
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
