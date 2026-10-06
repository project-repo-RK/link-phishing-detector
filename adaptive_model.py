# Fit each forest on exactly the available feature columns, never guessed inputs.
import json
from functools import lru_cache
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

from train import evaluate

ROOT = Path(__file__).resolve().parent
METADATA = json.loads((ROOT / 'models' / 'metadata.json').read_text())


@lru_cache(maxsize=1)
def training_split():
    # Retain the original 70/30 split. No test rows are used to fit a model.
    data = pd.read_csv(ROOT / 'data' / 'phishing_websites.csv')
    return train_test_split(data.drop(columns='Result'), data.Result, train_size=0.7, random_state=42)


@lru_cache(maxsize=8)
def model_for_columns(columns):
    # Cache a small number of feature combinations in memory, not submitted URLs.
    standard = ROOT / 'models' / 'collected_features.json'
    if standard.exists():
        saved = json.loads(standard.read_text())
        if list(columns) == saved['features']:
            return joblib.load(ROOT / 'models' / 'collected_random_forest.joblib'), saved['metrics']
    X_train, X_test, y_train, y_test = training_split()
    model = RandomForestClassifier(n_estimators=250, max_depth=22,
                     class_weight='balanced_subsample', random_state=42, n_jobs=2)
    model.fit(X_train[list(columns)], y_train)
    metrics = evaluate(model, X_test[list(columns)], y_test)
    return model, metrics


def predict_collected(values):
    # Validate measured codes against the actual CSV before using them.
    for name, value in values.items():
        if name not in METADATA['allowed_values'] or value not in METADATA['allowed_values'][name]:
            raise ValueError('The collected feature encoding does not match the dataset: ' + name)
    columns = tuple(name for name in METADATA['full_features'] if name in values)
    if len(columns) < 8:
        raise ValueError('Too few usable features were collected.')
    model, metrics = model_for_columns(columns)
    frame = pd.DataFrame([values], columns=list(columns))
    column = list(model.classes_).index(-1)
    score = float(model.predict_proba(frame)[0, column])
    return score, list(columns), metrics
