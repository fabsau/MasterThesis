# src/s1_pipeline/config.py
import os, logging

# ── General ───────────────────────────────────────────────────────────────────
LOG_LEVEL = logging.INFO

# ── SentinelOne Export ───────────────────────────────────────────────────────
VERIFY_SSL         = True
PAGE_LIMIT         = 1000
NOTE_PAGE          = 1000
MAX_WORKERS        = 200
DV_TIMEOUT         = 120
MAX_INIT_RETRY     = 5
LOOKBACK_DAYS      = 90
OUTPUT_FILE        = "./data/raw.json"
IGNORE_FIELDS      = []
IGNORE_NESTED_FIELDS = []

# ── Look-back Maximums ───────────────────────────────────────────────────────
MAX_INCIDENT_LOOKBACK_DAYS = 365
MAX_DEEPVIS_LOOKBACK_DAYS  = 90

# ── Postgres Database Settings ─────────────────────────────────────────────────
DB_HOST           = os.getenv("DB_HOST",     "localhost")
DB_PORT           = int(os.getenv("DB_PORT", 5432))
DB_NAME           = os.getenv("DB_NAME",     "catlyst")
DB_USER           = os.getenv("DB_USER",     "catlyst")
DB_PASSWORD       = os.getenv("DB_PASSWORD", "9KaCMz89d9548xx22xiSB6VT")
# Use this everywhere
DB_CONN_STR       = (
    f"postgresql://{DB_USER}:{DB_PASSWORD}"
    f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
# Table names (you can also namespace with a schema if you like)
DB_TABLE_THREATS  = os.getenv("DB_TABLE_THREATS",  "raw_threats")

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
ID_FIELD        = "threatInfo.threatId"
ISO_FORMAT      = "%Y-%m-%dT%H:%M:%SZ"

# ── CatBoost ─────────────────────────────────────────────────────────────────
DEFAULT_TRAIN_JSON   = "./data/splits/temporal-group/train.json"
DEFAULT_TEST_JSON    = "./data/splits/temporal-group/test.json"
DEFAULT_MODEL_OUT    = "./models/s1_fp_detector.cbm"
DEFAULT_RESULTS_DIR  = "./results"
DEFAULT_THREADS      = max(1, os.cpu_count() - 1)

CATBOOST_PARAMS = {
    "iterations":            1000,
    "learning_rate":         0.1,
    "depth":                 6,
    "l2_leaf_reg":           3,
    "border_count":          64,
    "random_seed":           42,
    "eval_metric":           "AUC",
    "early_stopping_rounds": 50,
    "logging_level":         "Silent",
}

ID_COLS = [
    "thr_id",                # The raw top-level threat id from the export
    "threatInfo_threatId",   # Internal unique threat identifier
    "threatInfo_sha1",       # Cryptographic hash – a unique fingerprint
    "threatInfo_sha256",     # Alternate hash, identifier and potential leak of artifact info
    "threatInfo_md5",        # MD5 hash of the file
    "threatInfo_createdAt",  # Timestamp at which threat was created (can leak time trends)
    "threatInfo_storyline",  # Grouping or storyline field that if included may spur shortcuts,
]

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

# ── Whitelist for raw export ───────────────────────────────────────────────────
WHITELIST_FIELDS = [
    "threatInfo.threatId",
    "threatInfo.storyline",
    "threatInfo.createdAt",
    "threatInfo.analystVerdict",
    "threatInfo.detectionEngines",
    "threatInfo.sha1",
    "threatInfo.sha256",
    "threatInfo.md5",
    "deepVisibilityEvents",
    "indicators",
    "notes",
]

# ───── Deep Visibility Columns & Sort ─────
DV_COLUMNS = [
    "event.type",
    "event.category",
    "severity",
    "dataSource.category",
    "dataSource.name",
    "dataSource.vendor",
    "endpoint.os",
    "endpoint.type",
    "os.name",
    "src.process.childProcCount",
    "src.process.crossProcessCount",
    "src.process.crossProcessDupRemoteProcessHandleCount",
    "src.process.crossProcessDupThreadHandleCount",
    "src.process.crossProcessOpenProcessCount",
    "src.process.crossProcessOutOfStorylineCount",
    "src.process.crossProcessThreadCreateCount",
    "src.process.moduleCount",
    "src.process.dnsCount",
    "src.process.netConnCount",
    "src.process.netConnInCount",
    "src.process.netConnOutCount",
    "src.process.registryChangeCount",
    "src.process.tgtFileCreationCount",
    "src.process.tgtFileDeletionCount",
    "src.process.tgtFileModificationCount",
    "src.process.indicatorBootConfigurationUpdateCount",
    "src.process.indicatorEvasionCount",
    "src.process.indicatorExploitationCount",
    "src.process.indicatorGeneralCount",
    "src.process.indicatorInfostealerCount",
    "src.process.indicatorInjectionCount",
    "src.process.indicatorPersistenceCount",
    "src.process.indicatorPostExploitationCount",
    "src.process.indicatorRansomwareCount",
    "src.process.indicatorReconnaissanceCount",
    "src.process.integrityLevel",
    "src.process.isNative64Bit",
    "src.process.isRedirectCmdProcessor",
    "src.process.isStorylineRoot",
    "src.process.signedStatus",
    "src.process.verifiedStatus",
    "tgt.file.extension",
    "tgt.file.isExecutable",
    "tgt.file.type",
    "tgt.file.size",
    "src.port.number",
    "dst.port.number",
    "event.network.direction",
    "event.network.protocolName",
    "event.network.connectionStatus",
    "event.dns.protocol",
    "event.dns.responseCode",
    "event.login.isAdministratorEquivalent",
    "event.login.loginIsSuccessful",
    "event.login.type"
]

DV_SORT = "event.time"


# ── ETL Configuration ────────────────────────────────────────────────────────

# Path where your raw export lands (could be a single JSON array or a folder
# of individual .json files)
RAW_JSON_PATH       = "./data/splits/temporal-group/train.json"

# Where to write the flat, per‐threat feature CSV
FEATURES_OUTPUT_CSV = "./data/staging/features.csv"

# Which top‐level keys to include (you already have WHITELIST_FIELDS)
ETL_TOP_LEVEL_FIELDS = [
    "threatInfo", "deepVisibilityEvents", "indicators", "notes"
]

# Which process‐level numeric fields to aggregate
ETL_PROC_NUMERIC = [
    fld for fld in DV_COLUMNS
    if fld.startswith("src.process.")
]

# Which deep‐visibility categories to one‐hot/count
# (we’ll auto‐discover categories at runtime, so none hard–coded here)

# Maximum length of the concatenated notes text
ETL_NOTES_MAX_LEN = 5000

# ── TF-IDF / Text Vectorization ────────────────────────────────────────────────
TFIDF_MAX_FEATURES    = 500
TFIDF_NGRAM_RANGE     = (1, 2)
# 'german', 'english', None, or supply your own list of tokens
TFIDF_STOP_WORDS      = "german"

# ── SMOTE (optional balancing) ────────────────────────────────────────────────
SMOTE_SAMPLING_STRATEGY = 0.3
SMOTE_RANDOM_STATE      = 42

# ── Cross-Validation ───────────────────────────────────────────────────────────
CV_FOLDS        = 5
CV_SHUFFLE      = True
CV_RANDOM_STATE = 42

# ── Output paths ──────────────────────────────────────────────────────────────
DEFAULT_MODEL_OUT      = "./models/s1_fp_detector.cbm"
DEFAULT_TFIDF_OUT      = "./models/s1_fp_detector.tfidf.pkl"