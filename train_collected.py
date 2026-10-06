# Save the forest for all automatically encodable features and its held-out results.
import json
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier

from adaptive_model import METADATA, training_split
from collector import COLLECTABLE_FEATURES
from train import evaluate

root = Path(__file__).resolve().parent
columns = [name for name in METADATA['full_features'] if name in COLLECTABLE_FEATURES]
X_train, X_test, y_train, y_test = training_split()
model = RandomForestClassifier(n_estimators=250, max_depth=22,
                 class_weight='balanced_subsample', random_state=42, n_jobs=2)
model.fit(X_train[columns], y_train)
metrics = evaluate(model, X_test[columns], y_test)
joblib.dump(model, root / 'models' / 'collected_random_forest.joblib', compress=3)
report = {'features': columns, 'metrics': metrics,
          'note': 'Historical precomputed-feature test only; not live-URL extractor accuracy.'}
(root / 'models' / 'collected_features.json').write_text(json.dumps(report, indent=2) + '\n')
(root / 'results' / 'collected_metrics.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
