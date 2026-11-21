# HTTP Request Smuggling Playbook: Framing, Byte Counting, and CRLF Mechanics

## 1. Overview of HTTP Request Smuggling

HTTP request smuggling occurs when front-end (reverse proxy, CDN, or load balancer) and back-end (origin or application) servers disagree on where one HTTP request ends and the next begins. This ambiguity typically arises when two components interpret `Content-Length` (`CL`) and `Transfer-Encoding` (`TE`) headers differently, or when ambiguous header/newline parsing allows request boundaries to desynchronize.

### High-Level Desynchronization Concepts

* **CL.TE vs. TE.CL Ambiguity:** One layer prioritizes `Content-Length` while the next prioritizes `Transfer-Encoding: chunked`, causing leftover bytes in a connection buffer to be interpreted as the start of a subsequent request.
* **TE.TE Obfuscation:** Both layers support `Transfer-Encoding`, but variations in header formatting or whitespace lead one layer to ignore `Transfer-Encoding` and fall back to `Content-Length`.
* **Defensive Alignment:** End-to-end HTTP/2 or consistent HTTP/1.1 parsing, strict header normalization, rejecting ambiguous `CL` + `TE` combinations, and normalizing connection reuse reduce framing mismatches.

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

* **Body Payload / Wire Bytes:** `5` bytes (`Content-Length: 5`)
* **Total Request Wire Bytes:** $23 + 19 + 26 + 19 + 2 + 5 = \mathbf{94\text{ bytes}}$

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

* **Decoded Payload Bytes:** $5 + 5 = \mathbf{10\text{ bytes}}$
* **Chunked Body Wire Bytes:** $3 + 7 + 3 + 7 + 5 = \mathbf{25\text{ bytes}}$
* **Total Request Wire Bytes:** $23 + 19 + 28 + 2 + 25 = \mathbf{97\text{ bytes}}$

---

### C. Quick Comparison

| Metric | `Content-Length` | `Transfer-Encoding: chunked` |
| :--- | :--- | :--- |
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

* `%0D` = Carriage Return (`CR`, ASCII `13`, `\r`)
* `%0A` = Line Feed (`LF`, ASCII `10`, `\n`)
* `%0D%0A` = `CRLF` (`\r\n`)

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

### Defensive Practices

* Reject or strip `\r` and `\n` in header values and URL parameters before header construction.
* Avoid concatenating raw user input directly into HTTP headers; use framework header APIs and strict allowlists.
* Keep front-end and back-end servers updated so strict RFC header validation is enforced consistently.

---

## 4. Verification & Troubleshooting Checklist

* [ ] Confirm whether byte counts are measured on the decoded body or the full wire stream (including `\r\n` delimiters and chunk hex sizes).
* [ ] Verify multi-byte character encoding (such as UTF-8) when calculating `Content-Length`.
* [ ] Check how proxies and origin servers handle `Transfer-Encoding` alongside `Content-Length` or control characters (`%0D`, `%0A`).
* [ ] Ensure consistent HTTP version handling and connection reuse policies between edge and origin layers.

---

## 5. Reference URLs & Standards Documentation

* **RFC 9112 — HTTP/1.1 (Message Syntax and Routing):** https://www.rfc-editor.org/rfc/rfc9112
* **RFC 9110 — HTTP Semantics:** https://www.rfc-editor.org/rfc/rfc9110
* **OWASP — HTTP Request Smuggling:** https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
* **OWASP — CRLF Injection:** https://owasp.org/www-community/vulnerabilities/CRLF_Injection
* **PortSwigger Web Security Academy — HTTP Request Smuggling:** https://portswigger.net/web-security/request-smuggling
* **CWE-444 — Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling'):** https://cwe.mitre.org/data/definitions/444.html
* **CWE-113 — Improper Neutralization of CRLF Sequences in HTTP Headers:** https://cwe.mitre.org/data/definitions/113.html