# Collect features for submitted URLs, then score only the values actually available.
import argparse
import json

from adaptive_model import predict_collected
from collector import collect_features
from features import clean_url


def analyse_urls(text, network=True):
    # Keep each input on its own line to avoid silently dropping unusual URLs.
    urls = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        url, _, _ = clean_url(line)
        if url not in urls:
            urls.append(url)
    if not urls:
        raise ValueError('Paste a complete URL first.')
    if len(urls) > 3:
        raise ValueError('Analyse up to three URLs at a time, one per line.')
    results = []
    for url in urls:
        collected = collect_features(url, network=network)
        score, columns, metrics = predict_collected(collected['values'])
        results.append({
            'url': url, 'feature_url': collected['feature_url'], 'score': score,
            'features': collected['values'], 'model_features': columns,
            'feature_count': len(columns), 'unavailable': collected['unavailable'],
            'observations': collected['observations'], 'notes': collected['notes'],
            'redirects': collected['redirects'],
            'historical_test_accuracy': metrics['accuracy'],
        })
    results.sort(key=lambda item: item['score'], reverse=True)
    return {'status': 'scored', 'score': results[0]['score'], 'links': results,
            'network_collection': network,
            'notes': ['Scores use the features listed for each result. Dataset accuracy is not live-site accuracy.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Read public website evidence without executing its code.')
    parser.add_argument('url')
    parser.add_argument('--offline', action='store_true', help='Use URL text only; make no network requests.')
    args = parser.parse_args()
    print(json.dumps(analyse_urls(args.url, network=not args.offline), indent=2))
