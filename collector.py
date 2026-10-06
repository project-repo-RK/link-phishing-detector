# Collect website evidence as text. No browser, scripts, forms, or subresources run.
import json
import re
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from features import FEATURE_NAMES, domain_parser, is_ip_address, url_features
from safe_fetch import FetchError, fetch_text, resolve_public, validate_url

HTML_FEATURES = ['Favicon', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
                 'Submitting_to_email', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe']
COLLECTABLE_FEATURES = FEATURE_NAMES + HTML_FEATURES + [
    'SSLfinal_State', 'DNSRecord', 'age_of_domain', 'Domain_registeration_length']
# Redirect counts are collected separately: their CSV encoding is not documented reliably.
EXCLUDED_REASONS = {
    'Redirect': 'Count shown separately; the documented three-level rule disagrees with the binary CSV encoding.',
    'port': 'The original feature requires a service scan. No port scan is performed.',
    'Abnormal_URL': 'The original WHOIS identity comparison cannot reliably be reconstructed from redacted RDAP.',
    'web_traffic': 'Historical traffic-rank data is unavailable.',
    'Page_Rank': 'The historical PageRank measurement is unavailable.',
    'Google_Index': 'No reliable supported search-index lookup is configured.',
    'Links_pointing_to_page': 'No external backlink index is configured.',
    'Statistical_report': 'The original historical reputation reports are unavailable.',
}


def registered_domain(host):
    parts = domain_parser(host)
    return parts.top_domain_under_public_suffix or host.lower()


class PageParser(HTMLParser):
    # Record source attributes and inline script text without executing any of it.
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources = []
        self.anchors = []
        self.tag_links = []
        self.favicons = []
        self.forms = []
        self.attributes = []
        self.scripts = []
        self.in_script = False
        self.iframe = False
        self.base = None

    def handle_starttag(self, tag, attrs):
        attrs = {key: value or '' for key, value in attrs}
        self.attributes.append(attrs)
        if tag == 'base' and self.base is None and attrs.get('href'):
            self.base = attrs['href']
        if tag in ('img', 'audio', 'video', 'source', 'embed') and attrs.get('src'):
            self.resources.append(attrs['src'])
        if tag == 'object' and attrs.get('data'):
            self.resources.append(attrs['data'])
        if tag == 'a':
            self.anchors.append(attrs.get('href', ''))
        if tag == 'form':
            self.forms.append(attrs.get('action', ''))
        if tag == 'iframe':
            self.iframe = True
        if tag == 'script':
            self.in_script = True
            if attrs.get('src'):
                self.tag_links.append(attrs['src'])
        if tag == 'link' and attrs.get('href'):
            self.tag_links.append(attrs['href'])
            if 'icon' in attrs.get('rel', '').lower().split():
                self.favicons.append(attrs['href'])
        if tag == 'meta' and attrs.get('content'):
            self.tag_links.extend(re.findall(r'https?://[^\s"\'<>;]+', attrs['content'], re.I))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == 'script':
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts.append(data)


def page_features(html, url):
    parser = PageParser()
    parser.feed(html)
    base = urljoin(url, parser.base) if parser.base else url
    site = registered_domain(urlsplit(url).hostname or '')

    def external(link):
        try:
            target = urlsplit(urljoin(base, link))
            if target.scheme in ('data', 'javascript', 'mailto', 'tel'):
                return False
            return bool(target.hostname) and registered_domain(target.hostname) != site
        except ValueError:
            return True

    def ratio(links, anchor=False):
        if not links:
            return 0.0
        bad = 0
        for link in links:
            empty = anchor and (not link.strip() or link.strip().startswith('#') or link.lower().startswith('javascript:'))
            bad += int(empty or external(link))
        return 100.0 * bad / len(links)

    values = {}
    reasons = {}
    raw = {}
    if parser.favicons:
        values['Favicon'] = -1 if any(external(link) for link in parser.favicons) else 1
    else:
        reasons['Favicon'] = 'No favicon declaration was present; no default icon was fetched.'
    resources = ratio(parser.resources)
    raw['external_resource_percent'] = round(resources, 2)
    # The document defines an intermediate 0 category, but this CSV has only -1/1.
    if resources < 22:
        values['Request_URL'] = 1
    elif resources > 61:
        values['Request_URL'] = -1
    else:
        reasons['Request_URL'] = 'Measured ratio is in the document\'s intermediate band, absent from the CSV.'
    anchors = ratio(parser.anchors, anchor=True)
    tags = ratio(parser.tag_links)
    raw['external_or_empty_anchor_percent'] = round(anchors, 2)
    raw['external_tag_link_percent'] = round(tags, 2)
    values['URL_of_Anchor'] = 1 if anchors < 31 else 0 if anchors <= 67 else -1
    values['Links_in_tags'] = 1 if tags < 17 else 0 if tags <= 81 else -1
    if any(not action.strip() or action.lower().startswith('about:blank') for action in parser.forms):
        values['SFH'] = -1
    elif any(external(action) for action in parser.forms):
        values['SFH'] = 0
    else:
        values['SFH'] = 1
    # A mailto contact link alone is not evidence that a form submits information by email.
    values['Submitting_to_email'] = -1 if any(action.lower().startswith('mailto:') for action in parser.forms) else 1
    events = '\n'.join(str(attrs.get('onmouseover', '')) for attrs in parser.attributes)
    script = '\n'.join(parser.scripts)
    values['on_mouseover'] = -1 if re.search(r'(?:window\.)?status\s*=', events, re.I) else 1
    right_click = any(re.search(r'(?:return\s+false|preventDefault)', attrs.get('oncontextmenu', ''), re.I) for attrs in parser.attributes)
    right_click = right_click or bool(re.search(r'(?:event|e)\.button\s*={2,3}\s*2', script))
    values['RightClick'] = -1 if right_click else 1
    popup = bool(re.search(r'window\.open\s*\(', script, re.I))
    if popup and re.search(r'<input\b', script, re.I):
        values['popUpWidnow'] = -1
    elif popup:
        reasons['popUpWidnow'] = 'A popup is referenced, but its form contents cannot be established without execution.'
    else:
        values['popUpWidnow'] = 1
    values['Iframe'] = -1 if parser.iframe else 1
    raw['html_scope'] = 'Static returned HTML only. External scripts and dynamic content were not loaded.'
    return values, reasons, raw


def date_value(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def registration_features(record, now=None):
    now = now or datetime.now(timezone.utc)
    dates = {}
    for event in record.get('events', []):
        if event.get('eventAction') in ('registration', 'expiration'):
            try:
                dates[event['eventAction']] = date_value(event['eventDate'])
            except (KeyError, ValueError, TypeError):
                pass
    values, raw = {}, {}
    if 'registration' in dates and dates['registration'] <= now:
        age = (now - dates['registration']).days
        raw['domain_age_days'] = age
        # The historical six-month threshold is approximated as 183 days.
        values['age_of_domain'] = 1 if age >= 183 else -1
    if 'expiration' in dates:
        days = (dates['expiration'] - now).days
        raw['registration_days_remaining'] = days
        values['Domain_registeration_length'] = 1 if days > 365 else -1
    return values, raw


_rdap_cache = {}
_bootstrap_cache = None


def rdap_features(host, deadline):
    global _bootstrap_cache
    domain = registered_domain(host)
    if is_ip_address(host) or not domain_parser(host).suffix:
        raise FetchError('No registrable public domain was identified for RDAP.')
    cached = _rdap_cache.get(domain)
    if cached and time.monotonic() - cached[0] < 3600:
        return registration_features(cached[1])
    # IANA supplies the registry endpoint; no guessed WHOIS server is contacted.
    if _bootstrap_cache and time.monotonic() - _bootstrap_cache[0] < 86400:
        bootstrap = _bootstrap_cache[1]
    else:
        response = fetch_text('https://data.iana.org/rdap/dns.json', deadline, 'application/json')
        if response['status'] != 200 or response.get('body_error'):
            raise FetchError('The RDAP registry list could not be read: ' + response.get('body_error', str(response['status'])))
        bootstrap = json.loads(response['body'])
        _bootstrap_cache = (time.monotonic(), bootstrap)
    endpoint = None
    tld = domain.rsplit('.', 1)[-1]
    for suffixes, endpoints in bootstrap['services']:
        if tld in suffixes:
            endpoint = next((base for base in endpoints if base.startswith('https://')), None)
            break
    if not endpoint:
        raise FetchError('No HTTPS RDAP registry was found for this domain.')
    response = fetch_text(endpoint.rstrip('/') + '/domain/' + domain, deadline, 'application/rdap+json,application/json')
    if response['status'] != 200 or response.get('body_error'):
        raise FetchError('RDAP did not return a usable domain record: ' + response.get('body_error', str(response['status'])))
    record = json.loads(response['body'])
    if not isinstance(record, dict) or record.get('objectClassName') != 'domain':
        raise FetchError('RDAP returned an unexpected record type.')
    if len(_rdap_cache) >= 256:
        _rdap_cache.pop(next(iter(_rdap_cache)))
    _rdap_cache[domain] = (time.monotonic(), record)
    return registration_features(record)


def collect_features(url, network=True):
    values = url_features(url)
    reasons = dict(EXCLUDED_REASONS)
    observations = {}
    notes = []
    feature_url = url
    if not network:
        reasons.update({name: 'Network collection was disabled.' for name in COLLECTABLE_FEATURES if name not in values})
        return {'values': values, 'unavailable': reasons, 'observations': observations,
                'notes': notes, 'feature_url': feature_url, 'redirects': []}
    deadline = time.monotonic() + 25
    chain = []
    try:
        normalized, host, port, _ = validate_url(url)
        addresses = resolve_public(host, port, deadline)
        # Resolving an IP literal is not a DNS record lookup.
        if not is_ip_address(host):
            values['DNSRecord'] = 1
        result = fetch_text(normalized, deadline, first_addresses=addresses)
        chain = result['chain']
        feature_url = result['url']
        host = urlsplit(feature_url).hostname
        # All model inputs refer to the final URL, not a mix of different domains.
        values = url_features(feature_url)
        if not is_ip_address(host):
            values['DNSRecord'] = 1
        observations['http_redirect_count'] = len(chain) - 1
        observations['http_status'] = result['status']
        certificate = result['certificate']
        if certificate:
            observations['tls_verified'] = True
            observations['certificate_issuer'] = str(certificate.get('issuer', ''))
            observations['certificate_not_before'] = certificate.get('notBefore')
            observations['certificate_not_after'] = certificate.get('notAfter')
            # Retain the literal historical certificate-age rule, not the modern
            # assumption that HTTPS alone means a legitimate website.
            try:
                age = (time.time() - ssl.cert_time_to_seconds(certificate['notBefore'])) / 86400
                values['SSLfinal_State'] = 1 if age >= 365 else -1
                observations['certificate_age_days'] = round(age, 1)
                notes.append('The historical TLS feature penalizes certificates under one year old. Modern legitimate certificates often fall in this category.')
            except (KeyError, ValueError):
                pass
        elif urlsplit(feature_url).scheme == 'http':
            values['SSLfinal_State'] = -1
        content_type = result['headers'].get('content-type', '').lower()
        if result.get('body_error'):
            notes.append('Page collection: ' + result['body_error'])
        if not result.get('body_error') and 200 <= result['status'] < 300 and ('text/html' in content_type or 'application/xhtml+xml' in content_type):
            charset = re.search(r'charset=["\']?([\w-]+)', content_type)
            encoding = charset.group(1) if charset else 'utf-8'
            try:
                html = result['body'].decode(encoding, errors='replace')
            except LookupError:
                html = result['body'].decode('utf-8', errors='replace')
            html_values, html_reasons, html_raw = page_features(html, feature_url)
            values.update(html_values)
            reasons.update(html_reasons)
            observations.update(html_raw)
        else:
            notes.append('HTTP ' + str(result['status']) + ': no complete usable HTML; page-content features were not inferred.')
    except (ValueError, OSError, TypeError) as error:
        notes.append('Page collection: ' + str(error))
        # An HTTP URL itself supplies the protocol feature even if the request failed.
        if urlsplit(url).scheme.lower() == 'http':
            values['SSLfinal_State'] = -1
    try:
        # Give registration its own budget even after a slow or failed page fetch.
        deadline = time.monotonic() + 20
        # Validate syntax; RDAP contacts the checked registry, not this site.
        _, host, port, _ = validate_url(feature_url)
        registration, raw = rdap_features(host, deadline)
        values.update(registration)
        observations.update(raw)
    except (ValueError, OSError, TypeError, KeyError) as error:
        notes.append('Domain records: ' + str(error))
    for name in COLLECTABLE_FEATURES:
        if name not in values:
            reasons.setdefault(name, 'The required evidence was unavailable or could not be read reliably.')
    return {'values': values, 'unavailable': reasons, 'observations': observations,
            'notes': notes, 'feature_url': feature_url, 'redirects': chain}
