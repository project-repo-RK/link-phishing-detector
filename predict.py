# Load the saved models and provide simple email and full-feature prediction functions.
import argparse
import json
from pathlib import Path

import joblib
import pandas as pd

from features import read_email, url_features

project_folder = Path(__file__).resolve().parent
metadata = json.loads((project_folder / 'models' / 'metadata.json').read_text())
url_model = joblib.load(project_folder / 'models' / 'url_random_forest.joblib')
full_model = joblib.load(project_folder / 'models' / 'website_random_forest.joblib')


def phishing_scores(model, rows):
    # The dataset uses -1 for phishing. Locate that class explicitly.
    phishing_column = list(model.classes_).index(-1)
    return model.predict_proba(rows)[:, phishing_column]


def analyse_email(text, sender='', reply_to='', subject=''):
    # Extract the actual links and keep header observations separate from the model.
    email = read_email(text, sender, reply_to, subject)
    results = []
    if email['links']:
        rows = []
        for url in email['links']:
            rows.append(url_features(url))
        frame = pd.DataFrame(rows, columns=metadata['url_features'])
        probabilities = phishing_scores(url_model, frame)
        for url, features, probability in zip(email['links'], rows, probabilities):
            results.append({'url': url, 'score': float(probability), 'features': features})
        results.sort(key=lambda result: result['score'], reverse=True)

    # The summary is the highest individual link score, not an email probability.
    return {
        'status': 'scored' if results else 'unable_to_assess',
        'score': results[0]['score'] if results else None,
        'links': results,
        'notes': email['notes'],
        'details': {'sender': email['sender'], 'reply_to': email['reply_to'], 'subject': email['subject']},
        'scope': 'Highest link score from an eight-feature URL model. Not an email phishing probability.',
    }


def predict_full_features(values):
    # Require all 30 measured website features when using the original model.
    expected = metadata['full_features']
    if not isinstance(values, dict) or set(values) != set(expected):
        raise ValueError('Provide exactly the 30 website feature names listed in models/metadata.json.')
    for name in expected:
        value = values[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value not in metadata['allowed_values'][name]:
            raise ValueError(f'Invalid value for {name}. Allowed: {metadata["allowed_values"][name]}')
    frame = pd.DataFrame([values], columns=expected)
    return {'phishing_score': float(phishing_scores(full_model, frame)[0]),
            'model': 'Original 30-feature random forest', 'calibrated': False}


# Use either a text email file or a JSON file containing the full website features.
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Score links in an email or a complete website feature row.')
    parser.add_argument('input', type=Path)
    parser.add_argument('--full-features', action='store_true')
    args = parser.parse_args()
    text = args.input.read_text(encoding='utf-8')
    result = predict_full_features(json.loads(text)) if args.full_features else analyse_email(text)
    print(json.dumps(result, indent=2))
