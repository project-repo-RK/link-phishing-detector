# Turn links in an email into the URL features available without visiting a site.
import ipaddress
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

import tldextract

# Use the package's bundled suffix list. Do not download updates or make requests.
domain_parser = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Keep these names in the same spelling and order as the supplied dataset.
FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'HTTPS_token',
]

# This local list is a practical approximation of the original shortening feature.
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'lnkd.in', 's.id', 'rb.gy',
    'tiny.cc', 'j.mp', 'v.gd', 'bl.ink', 'short.io', 't.ly', 'youtu.be',
}
URL_PATTERN = re.compile(r'(?:https?://|www\.)[^\s<>"\']+', re.IGNORECASE)


def clean_url(value):
    # Remove ordinary sentence punctuation without removing balanced URL brackets.
    value = unescape(value).strip().rstrip('.,;!?')
    for left, right in [('(', ')'), ('[', ']'), ('{', '}')]:
        while value.endswith(right) and value.count(right) > value.count(left):
            value = value[:-1]
    if value.lower().startswith('www.'):
        value = 'http://' + value
    if not value or len(value) > 8192 or any(c.isspace() for c in value):
        raise ValueError('The URL is empty, too long, or contains whitespace.')
    parts = urlsplit(value)
    if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
        raise ValueError('Only complete HTTP or HTTPS links are supported.')
    # Accessing port also checks that a supplied port is a valid number.
    parts.port
    host = unquote(parts.hostname).encode('idna').decode('ascii').lower().rstrip('.')
    if any(c in host for c in '/\\@?# ') or not host:
        raise ValueError('The URL hostname is invalid.')
    return value, parts, host


def is_ip_address(host):
    # Detect standard IPv4/IPv6 addresses and common numeric or hexadecimal forms.
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pieces = host.split('.')
        numeric = all(re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)', p) for p in pieces)
        return 1 <= len(pieces) <= 4 and numeric


def url_features(url):
    # Extract only the eight features that can be measured from the URL string.
    url, parts, host = clean_url(url)
    values = {}
    ip_host = is_ip_address(host)
    values['having_IP_Address'] = -1 if ip_host else 1

    # Follow the length thresholds given in the original feature document.
    if len(url) < 54:
        values['URL_Length'] = 1
    elif len(url) <= 75:
        values['URL_Length'] = 0
    else:
        values['URL_Length'] = -1

    shortened = any(host == name or host.endswith('.' + name) for name in SHORTENERS)
    values['Shortining_Service'] = -1 if shortened else 1
    values['having_At_Symbol'] = -1 if '@' in url else 1
    values['double_slash_redirecting'] = -1 if url.rfind('//') > 7 else 1
    values['Prefix_Suffix'] = -1 if '-' in host else 1

    # Exclude the public suffix and one leading www label when counting subdomains.
    # IP hosts have no DNS subdomains; their IP feature captures that distinction.
    subdomains = []
    if not ip_host:
        subdomain = domain_parser(host).subdomain
        subdomains = subdomain.split('.') if subdomain else []
        if subdomains and subdomains[0] == 'www':
            subdomains = subdomains[1:]
    if len(subdomains) == 0:
        values['having_Sub_Domain'] = 1
    elif len(subdomains) == 1:
        values['having_Sub_Domain'] = 0
    else:
        values['having_Sub_Domain'] = -1

    # This feature checks the hostname, not whether the link uses HTTPS.
    values['HTTPS_token'] = -1 if 'https' in host else 1
    return values


class EmailHTMLParser(HTMLParser):
    # Read links without rendering HTML, running scripts, or loading resources.
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text = []
        self.anchor = None
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script', 'style'):
            self.hidden += 1
        if tag == 'a' and not self.hidden:
            self.anchor = {'url': attrs.get('href', ''), 'label': ''}
            self.links.append(self.anchor)

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a':
            self.anchor = None

    def handle_data(self, text):
        if self.hidden:
            return
        if self.anchor is not None:
            self.anchor['label'] += text
        else:
            self.text.append(text)


def read_email(text, sender='', reply_to='', subject=''):
    # Accept a pasted body or raw email source with headers and MIME parts.
    bodies = [text]
    if re.match(r'^(?:from|to|subject|received|mime-version|content-type|date):', text, re.I):
        message = Parser(policy=policy.default).parsestr(text)
        sender = sender or str(message.get('From', ''))
        reply_to = reply_to or str(message.get('Reply-To', ''))
        subject = subject or str(message.get('Subject', ''))
        bodies = []
        for part in message.walk():
            if part.get_content_type() in ('text/plain', 'text/html') and part.get_content_disposition() != 'attachment':
                try:
                    bodies.append(part.get_content())
                except (LookupError, UnicodeError):
                    payload = part.get_payload(decode=True)
                    bodies.append(payload.decode('utf-8', errors='replace') if payload else '')

    # Collect real HTML destinations and ordinary links in the remaining text.
    candidates = []
    for body in bodies:
        if re.search(r'<(?:html|body|a|div|p)\b', body, re.I):
            parser = EmailHTMLParser()
            parser.feed(body)
            candidates.extend(parser.links)
            body = ' '.join(parser.text)
        for match in URL_PATTERN.finditer(body):
            candidates.append({'url': match.group(), 'label': ''})

    links = []
    ignored = 0
    seen = set()
    notes = []
    for candidate in candidates:
        try:
            url, parts, host = clean_url(candidate['url'])
        except (ValueError, UnicodeError):
            ignored += 1
            continue
        if url in seen:
            continue
        seen.add(url)
        links.append(url)
        # A visible URL with a different destination is an observation, not a model feature.
        label_links = URL_PATTERN.findall(candidate['label'])
        if label_links:
            try:
                visible_host = clean_url(label_links[0])[2]
                if visible_host != host:
                    notes.append('An HTML link displays a different hostname from its destination.')
            except (ValueError, UnicodeError):
                pass

    # Compare supplied sender details separately; the model was not trained on headers.
    sender_address = parseaddr(sender)[1]
    reply_address = parseaddr(reply_to)[1]
    if '@' in sender_address and '@' in reply_address:
        if sender_address.rsplit('@', 1)[1].lower() != reply_address.rsplit('@', 1)[1].lower():
            notes.append('The sender and Reply-To fields use different domains. This can also occur in legitimate mail.')
    if ignored:
        notes.append(f'{ignored} unsupported or invalid link candidate(s) could not be scored.')
    if len(links) > 100:
        raise ValueError('This email contains more than 100 unique links. Analyse a smaller section.')
    return {'links': links, 'notes': list(dict.fromkeys(notes)),
            'sender': sender, 'reply_to': reply_to, 'subject': subject}
