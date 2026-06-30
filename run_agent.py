import sys
import os
from pathlib import Path

# If running inside PyInstaller bundle
if getattr(sys, "frozen", False):
    bundle_dir = Path(sys._MEIPASS)
else:
    bundle_dir = Path(__file__).resolve().parent

if str(bundle_dir) not in sys.path:
    sys.path.insert(0, str(bundle_dir))

soc_dir = bundle_dir / "deepcytes_soc_agent"
if soc_dir.exists() and str(soc_dir) not in sys.path:
    sys.path.insert(0, str(soc_dir))

import deepcytes_soc_agent.main

if __name__ == "__main__":
    sys.exit(deepcytes_soc_agent.main.main())
