# Exercise the network boundary and extraction rules without contacting suspect sites.
import json
import socket
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from safe_fetch import FetchError, validate_url, resolve_public, fetch_text, request_once
from collector import page_features, registration_features, collect_features, COLLECTABLE_FEATURES
from adaptive_model import predict_collected
from app import app

PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.215.14', 443))]


class FetchTests(unittest.TestCase):
    def test_blocked_destinations(self):
        urls = ['http://127.0.0.1/', 'http://10.1.2.3/', 'http://169.254.169.254/',
                'http://[::1]/', 'http://[::ffff:127.0.0.1]/', 'http://localhost/',
                'http://x.local/', 'http://2130706433/', 'http://127.1/', 'http://0x7f.0.0.1/',
                'ftp://example.com/', 'file:///etc/passwd', 'http://example.com:22/',
                'http://user:pass@example.com/', 'http://example.com\\@127.0.0.1/',
                'http://example.com/\r\nHeader: value']
        for url in urls:
            with self.subTest(url=url), self.assertRaises(FetchError):
                validate_url(url)

    def test_dns_mixed_addresses(self):
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 443))
        with patch('socket.getaddrinfo', return_value=PUBLIC + [private]):
            with self.assertRaises(FetchError):
                resolve_public('example.com', 443, time.monotonic() + 5)

    def test_connection_is_pinned(self):
        sock = MagicMock()
        response = MagicMock(status=200)
        response.getheaders.return_value = [('Content-Type', 'text/html')]
        response.read1.side_effect = [b'<html></html>', b'']
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch('safe_fetch.resolve_public', return_value=PUBLIC) as dns, patch('safe_fetch.socket.socket', return_value=sock), patch('safe_fetch.http.client.HTTPConnection', return_value=connection):
            request_once('http://example.com/', time.monotonic() + 10)
            dns.assert_called_once()
            sock.connect.assert_called_once_with(PUBLIC[0][4])
            self.assertIs(connection.sock, sock)
            self.assertNotIn('Cookie', connection.request.call_args.kwargs['headers'])
            self.assertNotIn('Authorization', connection.request.call_args.kwargs['headers'])

    def test_https_preserves_verification_and_sni(self):
        sock = MagicMock()
        tls = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value = tls
        tls.getpeercert.return_value = {'notBefore': 'Jan  1 00:00:00 2025 GMT'}
        response = MagicMock(status=200)
        response.getheaders.return_value = [('Content-Type','text/html')]
        response.read1.return_value = b''
        conn = MagicMock()
        conn.getresponse.return_value = response
        with patch('safe_fetch.resolve_public',return_value=PUBLIC), patch('safe_fetch.socket.socket',return_value=sock), patch('safe_fetch.ssl.create_default_context',return_value=context) as secure, patch('safe_fetch.http.client.HTTPConnection',return_value=conn):
            result = request_once('https://example.com/',time.monotonic()+5)
        secure.assert_called_once_with()
        context.wrap_socket.assert_called_once_with(sock,server_hostname='example.com')
        self.assertEqual(result['certificate']['notBefore'],'Jan  1 00:00:00 2025 GMT')

    def test_unsafe_redirect_is_not_followed(self):
        response = {'url':'https://example.com/', 'status':302,
                    'headers':{'location':'http://127.0.0.1/admin'}}
        with patch('safe_fetch.request_once', return_value=response) as request:
            with self.assertRaises(FetchError):
                fetch_text('https://example.com/', time.monotonic()+5)
            request.assert_called_once()

    def test_redirect_limit(self):
        def redirect(url, *args):
            return {'url':url,'status':302,'headers':{'location':'https://example.com/next'}}
        with patch('safe_fetch.request_once', side_effect=redirect) as request:
            with self.assertRaises(FetchError):
                fetch_text('https://example.com/', time.monotonic()+5)
            self.assertEqual(request.call_count, 6)

    def test_unsupported_encoding_and_large_responses_rejected(self):
        for headers in [[('Content-Encoding','br')],[('Content-Length','999999999')]]:
            sock = MagicMock()
            response = MagicMock(status=200)
            response.getheaders.return_value = [('Content-Type','text/html')] + headers
            conn = MagicMock()
            conn.getresponse.return_value = response
            with patch('safe_fetch.resolve_public',return_value=PUBLIC), patch('safe_fetch.socket.socket',return_value=sock), patch('safe_fetch.http.client.HTTPConnection',return_value=conn):
                result = request_once('http://example.com/',time.monotonic()+5)
                self.assertIn('body_error', result)
                response.read1.assert_not_called()
                conn.close.assert_called_once()

    def test_expired_deadline(self):
        with self.assertRaises(FetchError):
            resolve_public('example.com',443,time.monotonic()-1)


class ExtractorTests(unittest.TestCase):
    def test_source_features(self):
        html = '''<link rel="icon" href="https://other.net/favicon.ico">
        <img src="https://other.net/a.png"><a href="#">test</a>
        <form action="mailto:test@example.com"></form><iframe src="/frame"></iframe>
        <p onmouseover="window.status='hidden'" oncontextmenu="return false">test</p>'''
        values, missing, raw = page_features(html,'https://example.com/')
        for name in ['Favicon','Request_URL','URL_of_Anchor','Submitting_to_email','Iframe','on_mouseover','RightClick']:
            self.assertEqual(values[name],-1,name)
        self.assertEqual(raw['external_resource_percent'],100)

    def test_ambiguous_resource_encoding_is_omitted(self):
        values, missing, _ = page_features('<img src="https://other.net/a"><img src="/a">','https://example.com/')
        self.assertNotIn('Request_URL',values)
        self.assertIn('Request_URL',missing)

    def test_missing_favicon_and_popup_are_not_invented(self):
        values, missing, _ = page_features('<script>window.open("/next")</script>', 'https://example.com/')
        self.assertNotIn('Favicon',values)
        self.assertNotIn('popUpWidnow',values)
        self.assertIn('popUpWidnow',missing)
        page_features('<form action><p onmouseover><link rel>', 'https://example.com/')

    def test_domain_dates(self):
        now=datetime(2026,10,6,tzinfo=timezone.utc)
        record={'events':[{'eventAction':'registration','eventDate':'2020-01-01T00:00:00Z'},
                          {'eventAction':'expiration','eventDate':'2029-01-01T00:00:00Z'}]}
        values, _=registration_features(record,now)
        self.assertEqual(values,{'age_of_domain':1,'Domain_registeration_length':1})
        self.assertEqual(registration_features({},now)[0],{})

    def test_offline_makes_no_network_requests(self):
        with patch('socket.socket.connect',side_effect=AssertionError('Network attempted')):
            result=collect_features('https://example.com/',network=False)
        self.assertEqual(len(result['values']),8)

    def test_failed_fetch_has_no_fake_html_features(self):
        with patch('collector.resolve_public',side_effect=FetchError('Blocked')), patch('collector.rdap_features', side_effect=FetchError('Unavailable')):
            result=collect_features('https://example.com/')
        self.assertEqual(len(result['values']),8)
        self.assertNotIn('SFH',result['values'])

    def test_final_destination_features_are_consistent(self):
        response={'url':'https://final-domain.net/', 'status':200,
                  'chain':[{'url':'http://start.com/','status':302},{'url':'https://final-domain.net/','status':200}],
                  'headers':{'content-type':'text/html'},'body':b'<a href="/home">home</a>', 'certificate':None}
        with patch('collector.resolve_public',return_value=PUBLIC),patch('collector.fetch_text',return_value=response),patch('collector.rdap_features',return_value=({},{})):
            result=collect_features('http://start.com/')
        self.assertEqual(result['feature_url'],'https://final-domain.net/')
        self.assertEqual(result['values']['Prefix_Suffix'],-1)
        self.assertEqual(result['values']['URL_of_Anchor'],1)
        self.assertNotIn('Redirect',result['values'])
        self.assertEqual(result['observations']['http_redirect_count'],1)

    def test_complete_fixture_uses_all_22_features(self):
        response={'url':'https://example.com/', 'status':200,
                  'chain':[{'url':'https://example.com/','status':200}],
                  'headers':{'content-type':'text/html'},
                  'body':b'<link rel="icon" href="/icon"><img src="/photo"><a href="/home">home</a>',
                  'certificate':{'notBefore':'Jan  1 00:00:00 2020 GMT','notAfter':'Jan  1 00:00:00 2030 GMT','issuer':()}}
        records=({'age_of_domain':1,'Domain_registeration_length':1},{'domain_age_days':2000})
        with patch('collector.resolve_public',return_value=PUBLIC),patch('collector.fetch_text',return_value=response),patch('collector.rdap_features',return_value=records):
            result=collect_features('https://example.com/')
        self.assertEqual(set(result['values']),set(COLLECTABLE_FEATURES))
        score,columns,metrics=predict_collected(result['values'])
        self.assertEqual(len(columns),22)
        self.assertAlmostEqual(metrics['accuracy'],0.9493518239372928)
        self.assertTrue(0<=score<=1)

    def test_exact_available_columns_are_used(self):
        values=collect_features('https://example.com/',network=False)['values']
        score, columns, metrics=predict_collected(values)
        self.assertEqual(set(columns),set(values))
        self.assertEqual(len(columns),8)
        self.assertTrue(0<=score<=1)
        self.assertAlmostEqual(metrics['accuracy'],0.7220379861320471)


class LocalAPITests(unittest.TestCase):
    def test_url_endpoint_and_origin(self):
        with app.test_client() as client:
            self.assertEqual(client.get('/').status_code,200)
            self.assertEqual(client.post('/analyse',json={'urls':'https://example.com/','network':False}).status_code,200)
            self.assertEqual(client.post('/analyse',json={'urls':'https://example.com/','network':'yes'}).status_code,400)
            self.assertEqual(client.post('/analyse',json={'urls':'https://example.com/'},headers={'Origin':'https://evil.example'}).status_code,403)
            self.assertEqual(client.get('/',headers={'Host':'evil.example'}).status_code,403)
            self.assertEqual(client.post('/analyse',json={'urls':'hello'}).status_code,400)
            self.assertIn('Content-Security-Policy',client.get('/').headers)


if __name__=='__main__':
    unittest.main()
