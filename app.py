# Serve the local URL detector. Collected remote content never enters the page as HTML.
from threading import BoundedSemaphore
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request
from analyse import analyse_urls

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024
collection_slot = BoundedSemaphore(1)


@app.before_request
def local_requests_only():
    # Reject DNS-rebinding Host headers and cross-origin browser submissions.
    if urlsplit('http://' + request.host).hostname not in ('127.0.0.1', 'localhost'):
        return jsonify(error='Use the local application address.'), 403
    origin = request.headers.get('Origin')
    if origin and origin != request.host_url.rstrip('/'):
        return jsonify(error='Cross-origin requests are blocked.'), 403


@app.after_request
def response_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/')
def index():
    return render_template('index.html')


@app.errorhandler(413)
def too_large(error):
    return jsonify(error='Submit up to three URLs. The request limit is 32 KB.'), 413


@app.post('/analyse')
def analyse():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('urls'), str):
        return jsonify(error='Paste a complete URL first.'), 400
    network = data.get('network', True)
    if not isinstance(network, bool):
        return jsonify(error='The network setting must be true or false.'), 400
    if not collection_slot.acquire(blocking=False):
        return jsonify(error='Another analysis is running. Try again when it finishes.'), 429
    try:
        result = analyse_urls(data['urls'], network=network)
        return jsonify(result)
    except (ValueError, UnicodeError) as error:
        return jsonify(error=str(error)), 400
    finally:
        collection_slot.release()


if __name__ == '__main__':
    print('Open http://127.0.0.1:5000. Network collection contacts submitted sites without rendering them.')
    app.run(host='127.0.0.1', port=5000, debug=False)
