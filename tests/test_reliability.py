# Check collection improvements without relying on public websites or malicious URLs.
import gzip
import json
import socket
import time
import unittest
import zlib
from unittest.mock import MagicMock, patch

import collector
from collector import collect_features, rdap_features
from safe_fetch import read_body, request_once, FetchError, MAX_BYTES
from test_collection import PUBLIC


class ReliabilityTests(unittest.TestCase):
    def body(self, data, encoding):
        response = MagicMock()
        response.read1.side_effect = [data, b'']
        return read_body(response, {'content-type':'text/html', 'content-encoding':encoding}, MagicMock(), time.monotonic()+5)

    def test_compression_roundtrip(self):
        html = b'<html><a href="/home">Home</a></html>' * 100
        self.assertEqual(self.body(gzip.compress(html), 'gzip'), html)
        self.assertEqual(self.body(zlib.compress(html), 'deflate'), html)

    def test_decompression_bomb_is_bounded(self):
        with self.assertRaisesRegex(FetchError, 'expanded'):
            self.body(gzip.compress(b'x' * (MAX_BYTES+1)), 'gzip')

    def test_truncated_compression_is_rejected(self):
        with self.assertRaises(FetchError):
            self.body(gzip.compress(b'page')[:-3], 'gzip')

    def test_ipv6_failure_falls_back_to_ipv4(self):
        ipv6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:4700:4700::1111',443,0,0))
        success = {'status':200, 'body':b'ok'}
        with patch('safe_fetch.request_address', side_effect=[FetchError('Connection unavailable'), success]) as request:
            result = request_once('https://example.com/',time.monotonic()+10,addresses=[ipv6]+PUBLIC)
        self.assertEqual(result,success)
        self.assertEqual(request.call_args_list[1].args[4],PUBLIC[0])

    def test_private_fallback_address_is_never_tried(self):
        private = (socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))
        with patch('safe_fetch.request_address') as request, self.assertRaises(FetchError):
            request_once('https://example.com/',time.monotonic()+5,addresses=PUBLIC+[private])
        request.assert_not_called()

    def test_tls_survives_body_failure(self):
        result = {'url':'https://example.com/', 'status':200,'headers':{'content-type':'text/html'},
                  'body':b'', 'body_error':'response body: timeout',
                  'certificate':{'notBefore':'Jan  1 00:00:00 2020 GMT'}, 'chain':[]}
        with patch('collector.resolve_public',return_value=PUBLIC), patch('collector.fetch_text',return_value=result), patch('collector.rdap_features',return_value=({},{})):
            collected = collect_features('https://example.com/')
        self.assertIn('SSLfinal_State',collected['values'])
        self.assertNotIn('SFH',collected['values'])
        self.assertTrue(any('timeout' in note for note in collected['notes']))

    def test_domain_records_independent_of_site_dns(self):
        def registry(host,deadline):
            self.assertGreater(deadline-time.monotonic(),19)
            return {'age_of_domain':1}, {}
        with patch('collector.resolve_public',side_effect=FetchError('DNS unavailable')), patch('collector.rdap_features',side_effect=registry):
            result=collect_features('https://example.com/')
        self.assertIn('age_of_domain',result['values'])
        self.assertNotIn('DNSRecord',result['values'])

    def test_request_retains_certificate_when_body_is_rejected(self):
        sock = MagicMock()
        context = MagicMock()
        context.wrap_socket.return_value = sock
        sock.getpeercert.return_value = {'notBefore':'Jan  1 00:00:00 2020 GMT'}
        response = MagicMock(status=200)
        response.getheaders.return_value = [('Content-Type','text/html'),('Content-Encoding','br')]
        conn = MagicMock()
        conn.getresponse.return_value = response
        with patch('safe_fetch.socket.socket',return_value=sock), patch('safe_fetch.ssl.create_default_context',return_value=context), patch('safe_fetch.http.client.HTTPConnection',return_value=conn):
            result=request_once('https://example.com/',time.monotonic()+5,addresses=PUBLIC)
        self.assertTrue(result['certificate'])
        self.assertEqual(result['status'],200)
        self.assertIn('Unsupported compression',result['body_error'])

    def test_compressed_page_reaches_html_extractor(self):
        html=b'<link rel="icon" href="/icon"><img src="/photo"><a href="/home">Home</a>'
        sock=MagicMock()
        context=MagicMock()
        context.wrap_socket.return_value=sock
        sock.getpeercert.return_value={'notBefore':'Jan  1 00:00:00 2020 GMT'}
        response=MagicMock(status=200)
        response.getheaders.return_value=[('Content-Type','text/html'),('Content-Encoding','gzip')]
        response.read1.side_effect=[gzip.compress(html),b'']
        conn=MagicMock()
        conn.getresponse.return_value=response
        records=({'age_of_domain':1,'Domain_registeration_length':1},{})
        with patch('collector.resolve_public',return_value=PUBLIC), patch('collector.rdap_features',return_value=records), patch('safe_fetch.socket.socket',return_value=sock), patch('safe_fetch.ssl.create_default_context',return_value=context), patch('safe_fetch.http.client.HTTPConnection',return_value=conn):
            result=collect_features('https://example.com/')
        self.assertEqual(len(result['values']),22)
        self.assertEqual(result['values']['Favicon'],1)

    def test_registry_cache_reuses_success_only(self):
        bootstrap={'services':[[['com'],['https://registry.example.com/']]]}
        record={'objectClassName':'domain','events':[{'eventAction':'registration','eventDate':'2020-01-01T00:00:00Z'}]}
        responses=[{'status':200,'body':json.dumps(item).encode()} for item in (bootstrap,record)]
        with patch.object(collector,'_rdap_cache',{}), patch.object(collector,'_bootstrap_cache',None), patch('collector.fetch_text',side_effect=responses) as fetch:
            first=rdap_features('example.com',time.monotonic()+20)
            second=rdap_features('example.com',time.monotonic()+20)
        self.assertEqual(first,second)
        self.assertEqual(fetch.call_count,2)


if __name__=='__main__':
    unittest.main()
