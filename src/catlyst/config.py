# src/catlyst/config.py

from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).parent.parent.parent

# Load .env into os.environ immediately.
load_dotenv(PROJECT_ROOT / ".env")