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
LOOKBACK_DAYS      = 1
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
    "indicators"
    "notes",
]

# ───── Deep Visibility Columns & Sort ─────
# You can edit these columns as desired
DV_COLUMNS = [
    "event.time", "event.type", "event.category", "event.id", "group.id", "meta.event.name", "severity", "i.scheme", "i.version",
    "dataSource.category", "dataSource.name", "dataSource.vendor", "mgmt.id", "mgmt.osRevision", "mgmt.url", "site.id", "site.name",
    "account.id", "account.name", "packet.id", "process.unique.key", "threadId", "trace.id", "agent.uuid", "agent.version",
    "endpoint.name", "endpoint.os", "endpoint.type", "os.name", "src.process.user", "src.process.storyline.id", "src.process.childProcCount",
    "src.process.cmdline", "src.process.crossProcessCount", "src.process.crossProcessDupRemoteProcessHandleCount",
    "src.process.crossProcessDupThreadHandleCount", "src.process.crossProcessOpenProcessCount", "src.process.crossProcessOutOfStorylineCount",
    "src.process.crossProcessThreadCreateCount", "src.process.displayName", "src.process.dnsCount", "src.process.image.binaryIsExecutable",
    "src.process.image.extension", "src.process.image.md5", "src.process.image.path", "src.process.image.productVersion",
    "src.process.image.sha1", "src.process.image.sha256", "src.process.image.size", "src.process.image.type", "src.process.image.uid",
    "src.process.indicatorBootConfigurationUpdateCount", "src.process.indicatorEvasionCount", "src.process.indicatorExploitationCount",
    "src.process.indicatorGeneralCount", "src.process.indicatorInfostealerCount", "src.process.indicatorInjectionCount",
    "src.process.indicatorPersistenceCount", "src.process.indicatorPostExploitationCount", "src.process.indicatorRansomwareCount",
    "src.process.indicatorReconnaissanceCount", "src.process.integrityLevel", "src.process.isNative64Bit", "src.process.isRedirectCmdProcessor",
    "src.process.isStorylineRoot", "src.process.moduleCount", "src.process.name", "src.process.netConnCount", "src.process.netConnInCount",
    "src.process.netConnOutCount", "src.process.pid", "src.process.publisher", "src.process.registryChangeCount", "src.process.sessionId",
    "src.process.signedStatus", "src.process.startTime", "src.process.subsystem", "src.process.tgtFileCreationCount",
    "src.process.tgtFileDeletionCount", "src.process.tgtFileModificationCount", "src.process.uid", "src.process.verifiedStatus",
    "src.process.parent.cmdline", "src.process.parent.displayName", "src.process.parent.image.md5", "src.process.parent.image.path",
    "src.process.parent.image.sha1", "src.process.parent.image.sha256", "src.process.parent.image.size", "src.process.parent.image.type",
    "src.process.parent.image.uid", "src.process.parent.integrityLevel", "src.process.parent.isNative64Bit", "src.process.parent.isRedirectCmdProcessor",
    "src.process.parent.isStorylineRoot", "src.process.parent.name", "src.process.parent.pid", "src.process.parent.publisher",
    "src.process.parent.sessionId", "src.process.parent.signedStatus", "src.process.parent.startTime", "src.process.parent.storyline.id",
    "src.process.parent.subsystem", "src.process.parent.user", "tgt.process.cmdline", "tgt.process.displayName", "tgt.process.image.binaryIsExecutable",
    "tgt.process.image.md5", "tgt.process.image.path", "tgt.process.image.sha1", "tgt.process.image.sha256", "tgt.process.integrityLevel",
    "tgt.process.isNative64Bit", "tgt.process.isRedirectCmdProcessor", "tgt.process.isStorylineRoot", "tgt.process.name", "tgt.process.pid",
    "tgt.process.publisher", "tgt.process.sessionId", "tgt.process.signedStatus", "tgt.process.startTime", "tgt.process.storyline.id",
    "tgt.process.subsystem", "tgt.process.uid", "tgt.process.user", "tgt.process.verifiedStatus", "tgt.file.creationTime", "tgt.file.extension",
    "tgt.file.id", "tgt.file.isExecutable", "tgt.file.location", "tgt.file.md5", "tgt.file.modificationTime", "tgt.file.oldPath", "tgt.file.path",
    "tgt.file.sha1", "tgt.file.sha256", "tgt.file.size", "tgt.file.type", "tgt.file.description", "tgt.file.internalName", "tgt.file.isSigned",
    "src.ip.address", "src.port.number", "dst.ip.address", "dst.port.number", "event.network.direction", "event.network.protocolName",
    "event.network.connectionStatus", "event.dns.protocol", "event.dns.provider", "event.dns.request", "event.dns.response", "event.dns.responseCode",
    "registry.keyPath", "registry.oldValue", "registry.oldValueFullSize", "registry.oldValueIsComplete", "registry.oldValueType", "registry.value",
    "registry.valueFullSize", "registry.valueIsComplete", "registry.valueType", "task.name", "task.path", "indicator.category", "indicator.name",
    "indicator.description", "indicator.metadata", "event.login.accountDomain", "event.login.accountName", "event.login.accountSid",
    "event.login.isAdministratorEquivalent", "event.login.loginIsSuccessful", "event.login.sessionId", "event.login.type", "event.login.userName",
    "cmdScript.applicationName", "cmdScript.content", "cmdScript.isComplete", "cmdScript.originalSize", "cmdScript.sha256"
]
DV_SORT = "event.time"  # If you wish to change sorting, just update this

# ───── Helper For Query Construction ─────
def get_column_clause():
    cols = DV_COLUMNS if isinstance(DV_COLUMNS, str) else ", ".join(DV_COLUMNS)
    clause = f"| columns {cols}"
    if DV_SORT:
        clause += f" | sort {DV_SORT}"
    return clause