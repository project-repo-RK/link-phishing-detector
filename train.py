# Reproduce the selected model settings and save both full and URL-only forests.
import hashlib
import json
from pathlib import Path

import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier

from features import FEATURE_NAMES

project_folder = Path(__file__).resolve().parent


def evaluate(model, X_test, y_test):
    # Explicitly find the phishing class rather than assuming a probability column.
    prediction = model.predict(X_test)
    phishing_column = list(model.classes_).index(-1)
    probability = model.predict_proba(X_test)[:, phishing_column]
    return {
        'accuracy': accuracy_score(y_test, prediction),
        'f1_legitimate_original_metric': f1_score(y_test, prediction, pos_label=1),
        'f1_phishing': f1_score(y_test, prediction, pos_label=-1),
        'precision_phishing': precision_score(y_test, prediction, pos_label=-1),
        'recall_phishing': recall_score(y_test, prediction, pos_label=-1),
        'auroc_phishing': roc_auc_score(y_test == -1, probability),
        'confusion_matrix_labels': [-1, 1],
        'confusion_matrix': confusion_matrix(y_test, prediction, labels=[-1, 1]).tolist(),
    }


def train_models():
    # Keep the original split unchanged so its results can be compared fairly.
    data_path = project_folder / 'data' / 'phishing_websites.csv'
    data = pd.read_csv(data_path)
    X = data.drop(columns='Result')
    y = data['Result']
    X_train, X_test, y_train, y_test = train_test_split(X, y, train_size=0.7, random_state=42)

    # These settings were selected in the supplied development notebook.
    models = {
        'logistic_regression': LogisticRegression(C=0.072, class_weight='balanced', random_state=42),
        'knn': KNeighborsClassifier(n_neighbors=1),
        'decision_tree': DecisionTreeClassifier(max_depth=24, class_weight='balanced', random_state=42),
        'random_forest_full': RandomForestClassifier(n_estimators=250, max_depth=22,
                         class_weight='balanced_subsample', random_state=42, n_jobs=2),
    }
    (project_folder / 'models').mkdir(exist_ok=True)
    (project_folder / 'results').mkdir(exist_ok=True)
    metrics = {}
    for name, model in models.items():
        print(f'Training {name}...', flush=True)
        model.fit(X_train, y_train)
        metrics[name] = evaluate(model, X_test, y_test)

    # Save the 30-feature winner before any dimensionality-reduction experiments.
    joblib.dump(models['random_forest_full'], project_folder / 'models' / 'website_random_forest.joblib', compress=3)

    # Train a separate model on just the measurable URL features.
    # Do not fill the other 22 features with guessed or neutral values.
    print('Training the eight-feature URL model...', flush=True)
    url_model = RandomForestClassifier(n_estimators=250, max_depth=22,
                    class_weight='balanced_subsample', random_state=42, n_jobs=2)
    url_model.fit(X_train[FEATURE_NAMES], y_train)
    metrics['random_forest_url_only'] = evaluate(url_model, X_test[FEATURE_NAMES], y_test)
    joblib.dump(url_model, project_folder / 'models' / 'url_random_forest.joblib', compress=3)

    # Record the schema, provenance, and independent held-out results.
    metadata = {
        'sklearn_version': sklearn.__version__,
        'dataset_sha256': hashlib.sha256(data_path.read_bytes()).hexdigest(),
        'training_rows': len(X_train), 'test_rows': len(X_test),
        'class_labels': {'-1': 'phishing', '1': 'legitimate'},
        'full_features': list(X.columns), 'url_features': FEATURE_NAMES,
        'allowed_values': {name: sorted(int(v) for v in X[name].unique()) for name in X.columns},
        'parameters': {'n_estimators': 250, 'max_depth': 22, 'class_weight': 'balanced_subsample', 'random_state': 42},
        'split': '70/30, random_state=42, no stratification; original notebook split',
        'probability_note': 'Uncalibrated random-forest scores, not validated email probabilities.',
        'model_selection_note': 'Full-model settings selected in the original notebook; URL-only settings reused, not independently tuned.',
    }
    (project_folder / 'models' / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (project_folder / 'results' / 'metrics.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(metrics, indent=2))


if __name__ == '__main__':
    train_models()
