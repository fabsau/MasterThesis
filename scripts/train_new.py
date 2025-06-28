# scipts/train_new.py
import pickle
from catlyst import config

import numpy as np
import pandas as pd

from sklearn.model_selection       import StratifiedKFold
from sklearn.metrics               import roc_auc_score, classification_report
from sklearn.feature_extraction.text import TfidfVectorizer
from nltk.corpus                   import stopwords
from imblearn.over_sampling        import SMOTE
from catboost                      import CatBoostClassifier

def load_data(path):
    df = pd.read_csv(path)
    # pull off label and raw text
    y = df.pop("label").astype(int).values
    text = df.pop("notes_text").fillna("").astype(str).values
    X_num = df.values
    feature_names = list(df.columns)
    return X_num, text, y, feature_names

def build_stop_words():
    sw = config.TFIDF_STOP_WORDS
    if isinstance(sw, list):
        return sw
    if sw == "german":
        return stopwords.words("german") + stopwords.words("english")
    if sw == "english":
        return stopwords.words("english")
    return None

def vectorize_text(corpus):
    stop_list = build_stop_words()
    tfv = TfidfVectorizer(
        max_features   = config.TFIDF_MAX_FEATURES,
        stop_words     = stop_list,
        ngram_range    = config.TFIDF_NGRAM_RANGE
    )
    X_tfidf = tfv.fit_transform(corpus).toarray()
    return X_tfidf, tfv

def main():
    # 1) Load features.csv
    X_num, text, y, num_feat_names = load_data(config.FEATURES_OUTPUT_CSV)
    print(f"[i] {X_num.shape[0]} rows × {X_num.shape[1]} numeric features loaded.")

    # 2) Vectorize notes_text
    # X_txt, tfv = vectorize_text(text) Remoed the notes
    print(f"[i] TF-IDF → {X_txt.shape[1]} text features")

    # 3) Merge
    # X = np.hstack([X_num, X_txt]) Removed the notes
    # all_feature_names = num_feat_names + list(tfv.get_feature_names_out())
    X = X_num
    all_feature_names = num_feat_names


    # 4) SMOTE?
    print("[i] Original class counts:", np.bincount(y))
    sm = SMOTE(
        sampling_strategy = config.SMOTE_SAMPLING_STRATEGY,
        random_state      = config.SMOTE_RANDOM_STATE
    )
    X_res, y_res = sm.fit_resample(X, y)
    print("[i] After SMOTE:", np.bincount(y_res))

    # 5) Stratified CV
    skf = StratifiedKFold(
        n_splits    = config.CV_FOLDS,
        shuffle     = config.CV_SHUFFLE,
        random_state= config.CV_RANDOM_STATE
    )
    aucs = []
    print("[i] Running CV…")
    for fold, (tr, va) in enumerate(skf.split(X_res, y_res), start=1):
        Xtr, Xva = X_res[tr], X_res[va]
        ytr, yva = y_res[tr], y_res[va]

        # auto class-weight: neg/pos
        neg, pos = np.bincount(ytr)
        wpos = float(neg / pos)

        model = CatBoostClassifier(
            **config.CATBOOST_PARAMS,
            class_weights = [1.0, wpos]
        )
        model.fit(
            Xtr, ytr,
            eval_set           = (Xva, yva),
            use_best_model     = True,
            verbose            = False
        )
        p = model.predict_proba(Xva)[:,1]
        auc = roc_auc_score(yva, p)
        print(f"  Fold {fold} AUC = {auc:.4f}")
        aucs.append(auc)

    print(f"[i] CV AUC = {np.mean(aucs):.4f} ± {np.std(aucs):.4f}")

    # 6) Final train on full resampled data
    print("[i] Training final model on full set…")
    neg, pos = np.bincount(y_res)
    wpos      = float(neg / pos)
    final_model = CatBoostClassifier(
        **config.CATBOOST_PARAMS,
        class_weights = [1.0, wpos]
    )
    final_model.fit(X_res, y_res, verbose=100)

    # 7) Report on resampled “train” set
    preds = final_model.predict(X_res)
    print("\n[i] Report on resampled set:")
    print(classification_report(y_res, preds, digits=4))

    # 8) Save model + TF-IDF
    os.makedirs(os.path.dirname(config.DEFAULT_MODEL_OUT), exist_ok=True)
    final_model.save_model(config.DEFAULT_MODEL_OUT)
    with open(config.DEFAULT_TFIDF_OUT, "wb") as f:
        pickle.dump(tfv, f)
    print(f"[✔] Model ⇒ {config.DEFAULT_MODEL_OUT}")
    print(f"[✔] TF-IDF ⇒ {config.DEFAULT_TFIDF_OUT}")

if __name__ == "__main__":
    main()