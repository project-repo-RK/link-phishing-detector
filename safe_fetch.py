# Fetch bounded text responses without rendering a page or running website code.
import http.client
import ipaddress
import queue
import re
import socket
import ssl
import threading
import time
import zlib
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5


class FetchError(ValueError):
    pass


def remaining(deadline):
    # Share one deadline across DNS, connections, redirects, and body reads.
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise FetchError('The collection time limit was reached.')
    return min(seconds, 5.0)


def public_ip(address):
    ip = ipaddress.ip_address(address)
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return public_ip(str(ip.ipv4_mapped))
        # Do not use IPv6 transition mechanisms to reach a different IPv4 address.
        if ip.sixtofour or ip.teredo or ip in ipaddress.ip_network('64:ff9b::/96'):
            return False
    return True


def validate_url(url):
    # Reject credentials, unusual schemes/ports, control characters, and local names.
    if len(url) > 8192 or re.search(r'[\x00-\x20\x7f\\]', url):
        raise FetchError('The URL contains unsupported characters or is too long.')
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
            raise FetchError('Use a complete HTTP or HTTPS URL.')
        if parts.username is not None or parts.password is not None:
            raise FetchError('Network fetching is disabled for URLs containing login credentials.')
        port = parts.port or (443 if parts.scheme.lower() == 'https' else 80)
        if port not in (80, 443):
            raise FetchError('Only web ports 80 and 443 may be contacted.')
        host = parts.hostname.encode('idna').decode('ascii').lower().rstrip('.')
        if '%' in host or host == 'localhost' or host.endswith(('.localhost', '.local', '.internal', '.home', '.lan')):
            raise FetchError('Local and internal hostnames are blocked.')
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            labels = host.split('.')
            if len(labels) < 2 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
                raise FetchError('The hostname is invalid.')
            # Ambiguous integer, octal, shortened and hexadecimal addresses are blocked.
            if all(re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)', label) for label in labels):
                raise FetchError('Non-standard numeric hostnames are blocked.')
        else:
            if not public_ip(str(address)):
                raise FetchError('Private, loopback, reserved, and special-use addresses are blocked.')
        host_header = '[' + host + ']' if ':' in host else host
        if parts.port:
            host_header += ':' + str(port)
        path = quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="/%:@!$&'()*+,;=?-._~")
        normalized = urlunsplit((parts.scheme.lower(), host_header, path, query, ''))
        return normalized, host, port, host_header
    except (UnicodeError, ValueError) as error:
        if isinstance(error, FetchError):
            raise
        raise FetchError('The URL could not be parsed.') from error


def resolve_public(host, port, deadline):
    # Bound DNS waiting. A daemon thread cannot hold up server shutdown.
    timeout = remaining(deadline)
    result = queue.Queue(maxsize=1)
    def lookup():
        try:
            result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as error:
            result.put(error)
    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    try:
        addresses = result.get(timeout=timeout)
    except queue.Empty as error:
        raise FetchError('DNS lookup timed out.') from error
    if isinstance(addresses, OSError):
        raise FetchError('DNS lookup did not return a usable address.')
    if not addresses or any(not public_ip(entry[4][0]) for entry in addresses):
        raise FetchError('DNS returned a private or otherwise blocked address.')
    return addresses


def read_body(response, headers, raw, deadline):
    # Bound both network bytes and expanded bytes, including compressed responses.
    if 'attachment' in headers.get('content-disposition', '').lower():
        raise FetchError('Attachment responses are not accepted.')
    media = headers.get('content-type', '').split(';')[0].strip().lower()
    if media not in ('text/html', 'application/xhtml+xml', 'application/json', 'application/rdap+json'):
        raise FetchError('Unsupported content type: ' + (media or 'missing'))
    encoding = headers.get('content-encoding', 'identity').lower().strip()
    if encoding not in ('identity', '', 'gzip', 'deflate'):
        raise FetchError('Unsupported compression: ' + encoding)
    length = headers.get('content-length')
    if length and (not length.isdigit() or int(length) > MAX_BYTES):
        raise FetchError('The downloaded response exceeds the 2 MB limit.')
    decoder = zlib.decompressobj(31 if encoding == 'gzip' else 15) if encoding in ('gzip', 'deflate') else None
    body = bytearray()
    downloaded = 0
    while True:
        raw.settimeout(remaining(deadline))
        chunk = response.read1(min(65536, MAX_BYTES + 1 - downloaded))
        if not chunk:
            break
        downloaded += len(chunk)
        if downloaded > MAX_BYTES:
            raise FetchError('The downloaded response exceeds the 2 MB limit.')
        body.extend(decoder.decompress(chunk, MAX_BYTES + 1 - len(body)) if decoder else chunk)
        if len(body) > MAX_BYTES or (decoder and decoder.unconsumed_tail):
            raise FetchError('The expanded response exceeds the 2 MB limit.')
    if decoder and (not decoder.eof or decoder.unused_data):
        raise FetchError('The compressed response is truncated or has trailing data.')
    if length and downloaded != int(length):
        raise FetchError('The response body was truncated.')
    return bytes(body)


def request_address(url, host, port, host_header, address_entry, deadline, accept):
    # Connect only to a checked numeric address. Keep the hostname for TLS and Host.
    family, kind, protocol, _, address = address_entry
    raw = socket.socket(family, kind, protocol)
    connection = None
    result = {'url': url, 'status': 0, 'headers': {}, 'body': b'',
              'certificate': None, 'ip': address[0]}
    stage = 'connection'
    def close_on_deadline():
        try:
            raw.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        raw.close()
    timer = threading.Timer(max(0.01, deadline - time.monotonic()), close_on_deadline)
    timer.daemon = True
    timer.start()
    try:
        raw.settimeout(remaining(deadline))
        raw.connect(address)
        if urlsplit(url).scheme == 'https':
            stage = 'TLS verification'
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            result['certificate'] = raw.getpeercert()
        stage = 'HTTP headers'
        connection = http.client.HTTPConnection(host, port, timeout=remaining(deadline))
        connection.sock = raw
        parts = urlsplit(url)
        target = parts.path + ('?' + parts.query if parts.query else '')
        connection.request('GET', target, headers={
            'Host': host_header, 'User-Agent': 'URLFeatureCollector/2.0',
            'Accept': accept, 'Accept-Encoding': 'gzip, deflate', 'Connection': 'close',
        })
        raw.settimeout(remaining(deadline))
        response = connection.getresponse()
        result['status'] = response.status
        result['headers'] = {key.lower(): value for key, value in response.getheaders()}
        stage = 'response body'
        if response.status not in (301, 302, 303, 307, 308):
            result['body'] = read_body(response, result['headers'], raw, deadline)
        return result
    except (OSError, http.client.HTTPException, FetchError, zlib.error) as error:
        message = stage + ': ' + str(error)
        # A body failure must not erase a verified certificate or HTTP status.
        if result['certificate'] or result['status']:
            result['body_error'] = message
            return result
        raise FetchError(message) from error
    finally:
        timer.cancel()
        if connection:
            connection.close()
        raw.close()


def request_once(url, deadline, accept='text/html,application/xhtml+xml', addresses=None):
    url, host, port, host_header = validate_url(url)
    addresses = addresses or resolve_public(host, port, deadline)
    if any(not public_ip(entry[4][0]) for entry in addresses):
        raise FetchError('A blocked address was supplied.')
    # Alternate address families so broken IPv6 does not consume every attempt.
    groups = [[a for a in addresses if a[0] == family] for family in (socket.AF_INET6, socket.AF_INET)]
    ordered = []
    for index in range(max(map(len, groups), default=0)):
        for group in groups:
            if index < len(group) and group[index] not in ordered:
                ordered.append(group[index])
    errors = []
    partial = None
    for entry in ordered[:6]:
        if partial and time.monotonic() >= deadline:
            return partial
        remaining(deadline)
        try:
            result = request_address(url, host, port, host_header, entry, deadline, accept)
            if result['status'] == 0 and result.get('body_error'):
                partial = result
                continue
            return result
        except FetchError as error:
            errors.append(str(error))
    if partial:
        return partial
    raise FetchError('All checked addresses failed: ' + '; '.join(errors))


def fetch_text(url, deadline, accept='text/html,application/xhtml+xml', first_addresses=None):
    # Follow redirects manually, validating and pinning the destination each time.
    chain = []
    for number in range(MAX_REDIRECTS + 1):
        result = request_once(url, deadline, accept, first_addresses if number == 0 else None)
        chain.append({'url': result['url'], 'status': result['status']})
        if result['status'] not in (301, 302, 303, 307, 308):
            result['chain'] = chain
            return result
        location = result['headers'].get('location')
        if not location:
            raise FetchError('A redirect did not provide a destination.')
        url = urljoin(result['url'], location)
        validate_url(url)
    raise FetchError('The redirect limit of five was reached.')
