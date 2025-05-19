import os, logging

# ── General ───────────────────────────────────────────────────────────────────
LOG_LEVEL = logging.INFO

# ── SentinelOne Export ───────────────────────────────────────────────────────
VERIFY_SSL         = True
PAGE_LIMIT         = 1000
NOTE_PAGE          = 1000
MAX_WORKERS        = 50
DV_TIMEOUT         = 15
MAX_INIT_RETRY     = 5
LOOKBACK_DAYS      = 30
OUTPUT_FILE        = "./data/raw.json"
IGNORE_FIELDS      = []
IGNORE_NESTED_FIELDS = []

# ── SplitTrainingData ────────────────────────────────────────────────────────
INPUT_FILE      = "./data/raw.json"
OUT_DIR         = "./data/splits"
TEST_SIZE       = 0.2
CUTOFF_DATE     = "2025-05-01"
METHODS         = ["random","group","time","temporal-group"]
SEED            = 42
MAX_THREATS     = None
TIME_FIELD      = "threatInfo.createdAt"
GROUP_FIELDS    = [
    "threatInfo.sha1",
    "threatInfo.sha256",
    "threatInfo.md5",
    "threatInfo.threatId",
]
ID_FIELD        = "id"
ISO_FORMAT      = "%Y-%m-%dT%H:%M:%SZ"

# ── CatBoost ─────────────────────────────────────────────────────────────────
DEFAULT_TRAIN_JSON   = "./data/train.json"
DEFAULT_TEST_JSON    = "./data/test.json"
DEFAULT_MODEL_OUT    = "./models/s1_fp_detector.cbm"
DEFAULT_RESULTS_DIR  = "./results"
DEFAULT_THREADS      = max(1, os.cpu_count() - 1)

# ── Inference ─────────────────────────────────────────────────────────────────
MODEL_PATH_DEFAULT      = DEFAULT_MODEL_OUT
META_PATH_DEFAULT       = os.path.join(os.path.dirname(DEFAULT_MODEL_OUT), "meta.pkl")
INPUT_JSON_DEFAULT      = DEFAULT_TEST_JSON
OUTPUT_JSON_DEFAULT     = os.path.join(DEFAULT_RESULTS_DIR, "test_inference.json")
NOVELTY_TRAIN_DEFAULT   = DEFAULT_TRAIN_JSON
ISO_CONT_DEFAULT        = 0.01
ISO_EST_DEFAULT         = 200
NOVELTY_THRESHOLD_DEFAULT = 0.0
PROB_THRESHOLD_DEFAULT  = 0.5
