# URL Phishing Detector

Paste a URL to collect website evidence and estimate phishing risk with a random
forest. The browser displays the model score, the exact features used, unavailable
features, redirect destinations, and collection notes.

The backend can gather **up to 22 of the original 30 model features**, plus a raw
HTTP redirect count. The original 30-feature model and development notebook are
also included. No missing feature is replaced with an invented safe or neutral value.

## Run locally

Use Python 3.11 or 3.12. Open a terminal in this project folder:

```bash
python -m venv .venv
```

Activate on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```bash
source .venv/bin/activate
```

Install and start:

```bash
python -m pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:5000**. Paste up to three full URLs, one per line, and click
**Analyse URLs**. Leave **Collect website and domain features** checked for the
expanded checks. Uncheck it for eight-feature URL-text-only analysis with no network
requests. Allow approximately 50 seconds per URL, including model fitting if needed.
Stop with Ctrl+C. If PowerShell blocks activation, use `.venv\Scripts\python.exe`
instead of `python`. If port 5000 is occupied, change the port in `app.py`.

## What contacts the website

Your browser stays on the local application. The Python backend makes bounded HTTP
GET requests to the submitted site, its allowed redirect destinations, IANA's RDAP
bootstrap service, and the relevant domain registry. It parses source as data.
It does not render the remote page, execute JavaScript, submit forms, load external
scripts/images/frames, or use your browser's cookies and sign-in sessions.

**This is still a network visit by the backend.** The site can see the public IP of
the computer running the app and the requested path/query. Requests can activate
tracking or one-time links. This reduces browser-execution risk; it is not a promise
of zero risk or anonymity. Use offline mode to avoid contacting the destination.

Network fetching is restricted to public destinations on ports 80/443. Every
redirect and DNS answer is checked. Connections use the validated numeric address
with the original hostname retained for TLS verification, preventing a second DNS
resolution between validation and connection. Local/private/special-use addresses,
credential-bearing URLs, and unusual ports are blocked. TLS verification is never
disabled. No proxies from environment variables are used.

Page collection has a 25-second deadline; domain collection has a separate
20-second deadline. Each request permits up to five redirects. Downloaded and
decompressed bodies are each limited to 2 MB. Gzip and zlib-wrapped deflate are
supported; attachments, unknown encodings, and incomplete bodies are rejected. There is one
active analysis at a time. The app binds to 127.0.0.1 and checks Host and Origin
headers. Fetched content is never inserted into the user interface as HTML.

## Collection reliability in version 2

- Alternate validated IPv6/IPv4 addresses are tried after connection failures
  (at most six addresses within the page deadline).
- Verified certificate information and HTTP status survive body-read failures.
- Domain registration checks work independently of website DNS and HTML retrieval.
- Successful RDAP records are cached in memory for one hour, up to 256 domains.
  The IANA registry list is cached for one day. No URL paths or page bodies are cached.
- Collection failures appear directly in each result, including the failing stage.

The collection rules and model feature definitions are unchanged. This version
improves evidence retrieval; it does not guarantee all 22 features or improve the
model's measured accuracy. It does not bypass bot challenges or execute JavaScript.

## Features and missing evidence

| Source | Measurements |
| --- | --- |
| URL text | IP host, length, shortening service, @ sign, extra slashes, hyphens, subdomains, HTTPS token |
| Returned HTML | Favicon origin, external resources/anchors/tag links, form actions, mail submission, status-bar/right-click/popup indicators, iframes |
| Network and certificate | Resolved public DNS addresses, verified certificate issuer/dates, HTTP redirects |
| Domain registry | Registration date and expiry through RDAP |

Features are based on the final fetched URL after redirects so URL, HTML, certificate,
and domain records do not describe different sites. The submitted URL and redirect
chain are shown separately. If fetching fails, only the evidence actually obtained
is used. Absence of a usable DNS response is not automatically encoded as phishing.

The original feature document and CSV disagree in two areas:

- `Request_URL`: the document's intermediate value 0 is absent from this CSV.
  Measurements in that band are shown but omitted from model input.
- `Redirect`: the CSV has only 0 and 1 while the document gives three categories
  without a compatible mapping. Raw redirect counts are shown but never guessed
  into a model code.

The service-scan `port` feature, redacted-WHOIS identity comparison, traffic ranking,
PageRank, search indexing, backlinks, and historical blacklist reports are unavailable
or would require additional services/operations. These are explicitly listed as
unavailable, not replaced with unrelated indicators. See `FEATURES.md` for rules.

## Model and performance

The full notebook selected 250 trees, maximum depth 22, balanced bootstrap samples,
and random seed 42. The expanded model keeps these settings and trains on the
22 collectable columns. The original 70/30 split is preserved: 7,738 training rows
and 3,317 test rows, with no test rows used for fitting.

| Model | Columns | Historical test accuracy | Phishing F1 |
| --- | ---: | ---: | ---: |
| Original full forest | 30 | 96.89% | 96.35% |
| Expanded feature forest | 22 | 94.94% | 94.15% |
| Offline URL-only forest | 8 | 72.20% | 71.24% |

These results use **precomputed historical dataset features**, not newly collected
URLs. They do not establish live-site detection accuracy. The original reported
97.3% is legitimate-class F1, not accuracy. Full metrics are in `results/`.

When some features are unavailable, the app trains a forest on exactly the available
columns using the original training rows. It evaluates that subset on the same
held-out rows and caches up to eight such models in memory. The standard 22-feature
model is prebuilt. The result lists the feature count and subset-specific historical
accuracy. The app does not choose feature sets by optimizing test performance.

Scores are uncalibrated `predict_proba` outputs for class -1 (phishing). The summary
is the highest per-URL score, not the probability that any site is malicious. A low
score is not evidence of safety.

## Important limits of these historical rules

- The supplied CSV has no raw URLs. End-to-end agreement between this extractor
  and the historical extraction process cannot be verified from these files.
- Static script checks do not observe dynamic or external-script behavior. Anti-bot
  pages, consent screens, redirects, and cloaking can hide the actual page.
- The historical TLS rule penalizes certificates less than one year old. Modern
  legitimate certificates commonly have shorter lifetimes. The app retains the
  literal age threshold, uses the system trust store as an issuer-trust approximation,
  and displays this limitation. Do not interpret a negative certificate feature as
  proof of phishing. HTTP-only pages receive the original negative protocol value.
- RDAP may be absent, redacted, rate-limited, or blocked. Six months is approximated
  as 183 days; a year as 365 days. Missing dates stay unavailable.
- Domain/CDN and shortening-service rules are approximations. Even legitimate sites
  use external resources, hyphens, short-lived certificates, and multiple subdomains.
- Fetching restrictions deliberately exclude local sites and some public sites.
  A blocked fetch is a collection limitation, not a phishing verdict.
- The original row-based split may share duplicated patterns; no domain/time split
  can be reconstructed without the missing original URLs and collection timestamps.

## Project files

| File | Purpose |
| --- | --- |
| `app.py`, `templates/`, `static/` | Local page and request handling |
| `safe_fetch.py` | Bounded HTTP requests, address checks, redirects, verified TLS |
| `collector.py` | HTML, certificate, DNS, and RDAP measurements |
| `features.py` | Original URL-text rules and legacy text parsing |
| `analyse.py` | Collection and prediction workflow; command-line entry point |
| `adaptive_model.py` | Forests trained on the exact available feature subset |
| `train_collected.py` | Rebuild the standard 22-feature model |
| `train.py`, `predict.py` | Original comparisons and strict full-feature/legacy CLI |
| `models/`, `results/` | Trained forests, schemas, measured results |
| `notebooks/model_training_and_development.ipynb` | Depersonalized original tuning and PCA experiments |
| `data/phishing_websites.csv` | Unchanged supplied dataset |
| `tests/` | Collection, encoding, network-boundary, and API tests |

## Command line and rebuilding

```bash
python analyse.py https://example.com/
python analyse.py https://example.com/ --offline
python predict.py examples/full_features.json --full-features
python train_collected.py
```

To rerun the original comparisons and both old forests, use `python train.py`.
To open the original notebook:

```bash
python -m pip install -r requirements-notebook.txt
python -m jupyterlab
```

The notebook exports the 30-feature forest before PCA overwrites the RF variable.
It does not rebuild the new collector forest; use `train_collected.py` for that.
Training overwrites the corresponding model/result files. Only load trusted joblib
files. Scikit-learn is pinned to the artifact version.

## Verification and attribution

```bash
python -m unittest discover -s tests -v
```

All 28 automated tests passed using controlled HTML, TLS/HTTP/DNS response
fixtures and the actual saved models. Browser checks also passed for offline
prediction, collection-failure handling, and the mobile layout. Live collection could not be validated in the build environment because its
DNS/network policy prevented direct public-host resolution. Such failures were
confirmed to produce explicit missing features rather than invented evidence.

The dataset is UCI Phishing Websites, CC BY 4.0. See `DATA_SOURCE.md` for author
credit and `FEATURES.md` for rule details. No code license is assigned. The original
presentation is excluded; the notebook uses generic filenames and paths. The
collector, interface, and documentation were prepared with ChatGPT assistance.
