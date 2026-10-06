# Collected features and encoding

The original dataset encodes feature categories as -1, 0, and 1, with different
allowed values per column. Zero is a defined category, not a missing-value code.
The collector can encode up to 22 columns. Any missing or ambiguous measurement is
omitted; a forest is fitted on exactly the columns available for that request.

## URL text: eight features

| Column | Rule |
| --- | --- |
| `having_IP_Address` | -1 for standard or common numeric/hex IP host forms; otherwise 1 |
| `URL_Length` | 1 below 54 characters; 0 from 54 through 75; -1 above 75 |
| `Shortining_Service` | -1 for a hostname in the local shortener list or its subdomains; otherwise 1 |
| `having_At_Symbol` | -1 for a literal @ sign; otherwise 1 |
| `double_slash_redirecting` | -1 if the last // begins after zero-based position 7; otherwise 1 |
| `Prefix_Suffix` | -1 for a hyphen in the hostname; otherwise 1 |
| `having_Sub_Domain` | 1 for no subdomain, 0 for one, -1 for more, ignoring one leading www and the public suffix |
| `HTTPS_token` | -1 for https within the hostname, regardless of the protocol; otherwise 1 |

A `www.` prefix without a scheme is normalized to `http://`. The tldextract bundled
public suffix snapshot is used without network updates; private suffix rules are
not enabled. IP hosts have no DNS subdomain labels. Shortener detection is a fixed
list and cannot be verified against the unavailable historical extraction code.
Credential-bearing and nonstandard-port URLs can be scored lexically but are not
fetched. The UI explains collection failures.

## Static HTML: up to ten additional features

| Column | Rule and limits |
| --- | --- |
| `Favicon` | -1 for a declared external favicon, 1 for same-domain declarations; missing when none is declared |
| `Request_URL` | External media/object-source ratio below 22% gives 1; above 61% gives -1; intermediate values are omitted because the CSV lacks the documented 0 category |
| `URL_of_Anchor` | External/empty/fragment/javascript anchor ratio: 1 below 31%, 0 through 67%, otherwise -1 |
| `Links_in_tags` | External link/script/meta URL ratio: 1 below 17%, 0 through 81%, otherwise -1 |
| `SFH` | -1 for empty/about:blank form actions; otherwise 0 for external actions; otherwise 1 |
| `Submitting_to_email` | -1 for mailto form actions; otherwise 1 based on observable source only |
| `on_mouseover` | -1 for a status assignment in an inline mouseover handler; otherwise 1 based on observable source |
| `RightClick` | -1 for common inline context-menu suppression or event.button==2 patterns; otherwise 1 based on observable source |
| `popUpWidnow` | -1 for window.open plus input markup in inline scripts; popup with unobservable contents is omitted; no detected popup gives 1 |
| `Iframe` | -1 for an iframe element in the returned source; otherwise 1 |

HTML `<base>` is respected when resolving relative attribute values. Domain
comparisons use the registrable domain, so ordinary subdomains are treated as the
same site. Ratios with no applicable elements are treated as zero. Empty form
actions are deliberately encoded using the old rule even though modern HTML can
legitimately submit to the current page.

These are **static approximations**, not observed runtime behavior. Server-side
mail functions, external scripts, and dynamically constructed elements are not
visible. The collector does not download external scripts, evaluate JavaScript,
follow frames, submit forms, or fetch favicons. Hidden behavior can therefore go
undetected; a positive category only describes the inspected source. Arbitrary
HTTP errors and non-HTML responses are not treated as legitimate empty pages.

## DNS, TLS and RDAP: up to four additional features

| Column | Rule and limits |
| --- | --- |
| `DNSRecord` | 1 when a domain resolves to checked public addresses; missing on failure or IP literals. Failed lookup is not assumed to prove nonexistence |
| `SSLfinal_State` | HTTP gives -1. Verified HTTPS certificates at least 365 days old give 1; younger ones give -1. Failed TLS verification gives missing rather than a guessed issuer category |
| `age_of_domain` | RDAP registration at least 183 days ago gives 1, otherwise -1; absent/future dates are omitted |
| `Domain_registeration_length` | RDAP expiry more than 365 days ahead gives 1, otherwise -1; absent expiry is omitted |

TLS issuer trust uses the system trust store, not the document's old named-issuer
list. Certificate age means elapsed time since notBefore. **This old age rule is
poorly suited to modern short-lived legitimate certificates.** Its negative category
is not proof of phishing. Certificate issuer and dates are shown as observations.
RDAP is located through IANA's bootstrap registry and queried over verified HTTPS.
Redacted, rate-limited, unsupported, and missing records remain unavailable.

## Eight excluded model columns

| Column | Reason |
| --- | --- |
| `Redirect` | HTTP redirect count is collected and shown, but the document's three categories do not establish the CSV's binary 0/1 mapping |
| `port` | Requires the original service-status/port scan; an explicit URL port is not equivalent |
| `Abnormal_URL` | The original WHOIS identity comparison is not reliably available from redacted records |
| `web_traffic` | No historical traffic-rank feed |
| `Page_Rank` | No equivalent historical PageRank measurement |
| `Google_Index` | No reliable supported index-membership API configured |
| `Links_pointing_to_page` | No external backlink database configured |
| `Statistical_report` | Original historical report membership cannot be reconstructed |

The implementation does not equate links on the page with backlinks to it, or the
presence of HTTPS with certificate trust. It does not use a URL's explicit port as
a substitute for a service scan. This avoids silently changing the meaning of the
training columns.

## Redirects, failure and network boundary

After a successful redirect chain, all scored URL, HTML, TLS and registration
features refer to the **final destination**. Submitted and final URLs are both
shown. If the chain fails, no partial page is mixed with another domain's features.
The raw count includes HTTP 301/302/303/307/308 responses only; JavaScript/meta
refresh redirects are not followed.

Requests are restricted to checked public IP addresses on web ports, with numeric
address pinning, per-hop checks, verified TLS, and bounded time and response size.
No browser credentials/cookies/referrer headers are sent. GET requests are still
visible to destinations and can trigger tracking or one-time-link actions. Read
`README.md` before using live collection.

Reference sources:

- Supplied *Phishing Websites Features* document, credited in `DATA_SOURCE.md`.
- IANA RDAP bootstrap: https://www.iana.org/assignments/rdap-dns
- OWASP SSRF prevention: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Version 2 retrieval supports bounded gzip/deflate, alternate checked IP addresses,
TLS evidence retained after body failures, and independently budgeted, cached RDAP.
These changes do not alter the feature encodings described above.
