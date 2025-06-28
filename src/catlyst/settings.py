# src/catlyst/settings.py

import catlyst.config

from functools import lru_cache
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

from pydantic_settings import BaseSettings

# ========== 1. DATABASE ==========
class DatabaseSettings(BaseSettings):
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "catlyst"
    db_user: str = "catlyst"
    db_password: str

    @property
    def url(self) -> str:
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    model_config = {"extra": "ignore"}

# ========== 2. SENTINELONE ==========
class SentinelOneSettings(BaseSettings):
    s1_management_url: str
    s1_api_token: str
    s1_api_version: str = "v2.1"
    s1_verify_ssl: bool = True
    s1_page_limit: int = 1000
    s1_note_page: int = 1000
    s1_max_workers: int = 200
    s1_dv_timeout: float = 120.0
    s1_max_init_retry: int = 5
    s1_lookback_days: int = 1
    s1_max_incident_lookback_days: int = 365
    s1_max_deepvis_lookback_days: int = 90

    model_config = {"extra": "ignore"}

# ========== 3. ETL / CLI ==========
class ETLSettings(BaseSettings):
    log_level: str = "DEBUG"
    iso_format: str = "%Y-%m-%dT%H:%M:%SZ"
    since_days: int = 1
    max_since_days: int = 365
    verdicts: List[str] = ["true_positive", "false_positive"]
    no_progress: bool = False
    workers: int = 200
    db_batch_size: int = 500
    output_file: str = "./data/raw.json"
    ignore_fields: List[str] = []
    ignore_nested_fields: List[str] = []

    model_config = {"extra": "ignore"}

# ========== 4. TABLE ==========
class TableSettings(BaseSettings):
    db_table_threats: str = "catlyst"
    model_config = {"extra": "ignore"}

# ========== 5. SPLIT ==========
class SplitSettings(BaseSettings):
    input_file: str = "./data/raw.json"
    out_dir: str = "./data/splits"
    test_size: float = 0.2
    cutoff_date: str = "2025-05-01"
    methods: List[str] = ["random", "group", "time", "temporal-group"]
    seed: int = 42
    max_threats: Optional[int] = None
    time_field: str = "threatInfo.createdAt"
    group_fields: List[str] = [
        "threatInfo.sha1", "threatInfo.sha256", "threatInfo.md5", "threatInfo.threatId"
    ]
    id_field: str = "threatInfo.threatId"

    model_config = {"extra": "ignore"}

# ========== 6. CATBOOST ==========
class CatBoostSettings(BaseSettings):
    train_json: str = "./data/splits/temporal-group/train.json"
    test_json: str = "./data/splits/temporal-group/test.json"
    model_out: str = "./models/s1_fp_detector.cbm"
    results_dir: str = "./results"
    threads: int = 8
    params: Dict[str, Any] = {
        "iterations": 1000,
        "learning_rate": 0.1,
        "depth": 6,
        "l2_leaf_reg": 3,
        "border_count": 64,
        "random_seed": 42,
        "eval_metric": "AUC",
        "early_stopping_rounds": 50,
        "logging_level": "Silent",
    }

    model_config = {"extra": "ignore"}

# ========== 7. INFERENCE ==========
class InferenceSettings(BaseSettings):
    model_path: Optional[str] = None
    meta_path: Optional[str] = None
    input_json: Optional[str] = None
    output_json: Optional[str] = None
    novelty_train: Optional[str] = None
    iso_cont_default: float = 0.01
    iso_est_default: int = 200
    novelty_threshold: float = 0.0
    prob_threshold: float = 0.5

    model_config = {"extra": "ignore"}

# ========== 8. ADDITIONALS ==========
class WhitelistSettings(BaseSettings):
    fields: List[str] = [
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
    model_config = {"extra": "ignore"}

class DeepVisSettings(BaseSettings):
    columns: List[str] = ["event.type", "event.category", "severity"]
    sort: str = "event.time"
    model_config = {"extra": "ignore"}

class FeatureSettings(BaseSettings):
    raw_json_path: str = "./data/splits/temporal-group/train.json"
    features_output_csv: str = "./data/staging/features.csv"
    etl_top_level_fields: List[str] = ["threatInfo", "deepVisibilityEvents", "indicators", "notes"]
    etl_proc_numeric: List[str] = []
    etl_notes_max_len: int = 5000
    model_config = {"extra": "ignore"}

class TFIDFSettings(BaseSettings):
    max_features: int = 500
    ngram_range: Tuple[int, int] = (1, 2)
    stop_words: Optional[str] = "german"
    model_config = {"extra": "ignore"}

class SmoteSettings(BaseSettings):
    sampling_strategy: float = 0.3
    random_state: int = 42
    model_config = {"extra": "ignore"}

class CVSettings(BaseSettings):
    folds: int = 5
    shuffle: bool = True
    random_state: int = 42
    model_config = {"extra": "ignore"}

# ========== FINAL AGGREGATOR ==========
@lru_cache()
def get_settings() -> SimpleNamespace:
    return SimpleNamespace(
        database=DatabaseSettings(),
        s1=SentinelOneSettings(),
        etl=ETLSettings(),
        tables=TableSettings(),
        split=SplitSettings(),
        catboost=CatBoostSettings(),
        inference=InferenceSettings(),
        whitelist=WhitelistSettings(),
        deepvis=DeepVisSettings(),
        feature=FeatureSettings(),
        tfidf=TFIDFSettings(),
        smote=SmoteSettings(),
        cv=CVSettings(),
    )