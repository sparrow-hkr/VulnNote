## Cookie Scope and Exploitation Techniques for Pentesters Basic Undrastanding

1. Understanding HostOnly: false

   - Definition: When a cookie has HostOnly: false, it means the cookie is accessible to the domain that set it and all its subdomains.
   - How it's set: This occurs when the Domain attribute is explicitly defined in the Set-Cookie header (e.g., Domain=example.com).
   - Security Implication: Subdomains can access and potentially manipulate cookies intended for the main domain.

2. Session Fixation Attack

   - What is Session Fixation?
   - Goal: Force a victim to use a known session ID so the attacker can hijack the session.
   - Mechanism:

     - Attacker sets a session cookie (e.g., via a subdomain or vulnerable endpoint).
     - Victim logs in using that session.
     - Attacker reuses the session ID to gain access.

   - Exploitation Steps

     - Identify: Check if the app accepts externally supplied session IDs.
     - Inject: Use a subdomain or open redirect to plant the session cookie.
     - Confirm: Observe if the session persists after login.
     - Exploit: Reuse the session ID to impersonate the victim.

   - Pentesting Tips
     - Look for login flows that don’t regenerate session IDs.
     - Test if cookies set on subdomains are accepted by the main domain (HostOnly: false).
     - Use tools like Burp Suite to manipulate Set-Cookie headers.

3. Cookie Propagation

   - What is Cookie Propagation?

     - Definition: Cookies set by one domain or subdomain are automatically sent to others within the same domain hierarchy.
     - When it happens: If HostOnly: false, cookies propagate to subdomains.

   - Exploitation Use Case

     - Scenario: A secure cookie set by example.com is accessible by admin.example.com.

   - Risk: If admin.example.com is vulnerable (e.g., XSS), attacker can steal cookies meant for example.com.

   - Pentesting Tips
     - Enumerate subdomains using tools like Amass, Sublist3r.
     - Test cookie visibility across subdomains.
     - Check for inconsistent cookie flags (Secure, HttpOnly, SameSite).

4. Cookie Injection

   - What is Cookie Injection?
     - Definition: Attacker sets or modifies cookies in the victim’s browser to influence application behavior.
   - Vectors:

     - Open redirect endpoints
     - Subdomain control
     - XSS vulnerabilities

   - Exploitation Use Case

     - Scenario: Attacker controls evil.example.com and sets a cookie sessionId=attacker123.

   - Impact: If example.com accepts this cookie (due to HostOnly: false), attacker can hijack the session.

   - Pentesting Tips
     - Test cookie overwrite via subdomains.
     - Use controlled environments to inject cookies and observe behavior.
     - Report any sensitive cookies lacking HostOnly, Secure, or HttpOnly.

# Pro

## Cookie Flags Cheat Sheet for Pentesters

## 1. HttpOnly

### Values

- **Set**: `HttpOnly` present
- **Not Set**: `HttpOnly` absent

### Purpose

- Prevents JavaScript from accessing cookies via `document.cookie`.

### Benefit

- Protects against **XSS-based session theft**.

### Risk if Missing

- Attacker can steal session cookies using XSS.

### Burp Suite Tip

- Use the **Proxy > HTTP history** tab to inspect `Set-Cookie` headers.
- Look for cookies missing `HttpOnly` and test with XSS payloads:
  ```html
  <script>
    alert(document.cookie);
  </script>
  ```

## 2. Secure

## Values

- **Set**: `Secure` present

- **Not Set**: `Secure` absent

## Purpose

- Ensures cookies are only sent over HTTPS.

## Benefit

- Prevents MitM attacks on insecure networks.

## Risk if Missing

- Cookies may be exposed over `HTTP`.

## Burp Suite Tip

- Use Repeater to send requests over HTTP and check if cookies are transmitted.
- Report if sensitive cookies (e.g., sessionId) are sent without Secure.

## 3. SameSite

## Values

- `Strict`: Cookie sent only for same-site requests.
- `Lax`: Cookie sent for top-level navigations (e.g., clicking a link).
- `None`: Cookie sent with all requests, including cross-site. Must be Secure.
- `Not Set`: Defaults vary by browser (often treated as Lax).

## Purpose

- Controls cross-site cookie transmission to mitigate `CSRF`.

## Benefit

- Reduces risk of CSRF attacks.

## Risk if Misconfigured

- CSRF may succeed if cookies are sent with cross-origin requests.

## Burp Suite Tip

- Use CSRF PoC Generator or manual requests from another domain.
- Observe if cookies are sent and actions are processed.

# Realistic Examples

- **Secure Cookie**

  - ```
    Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict
    ```

- **Insecure Cookie**

  - ```
    Set-Cookie: sessionId=abc123
    ```

- **CSRF-Protected Cookie**
  - ```
    Set-Cookie: authToken=xyz789; Secure; HttpOnly; SameSite=Strict
    ```
- **CSRF-Vulnerable Cookie**
  - ```
    Set-Cookie: authToken=xyz789; SameSite=None
    ```

# 4. Path Attribute

- What It Does
  - Defines the URL path for which the cookie is valid.
- Security Implication
  - Limits cookie exposure to specific application areas.
  - Prevents cookies from being sent to unrelated endpoints.
- Risk if Misused
  - Path=/ exposes cookies to all paths, increasing attack surface.
- **Realistic Example**
  - ```
    Set-Cookie: adminToken=admin123; Path=/admin; Secure; HttpOnly
    ```

## Burp Suite Testing

    - Use Repeater to send requests from **different paths**.
    - Observe if cookies are sent unnecessarily.
    - Report overexposed cookies.

# 5. Domain Attribute

- What It Does

  - Specifies which domain/subdomains can access the cookie.

- Security Implication

  - If set, cookie is accessible to subdomains (HostOnly: false).
  - Can lead to cookie injection or session fixation.

- Risk if Misused

  - Subdomains can overwrite or steal cookies.

- Realistic Example
  - Set-Cookie: sessionId=abc123; Domain=example.com; Path=/; Secure; HttpOnly

## Burp Suite Testing

    - Use Proxy to inspect Domain attribute.
    - Test cookie overwrite from subdomains.
    - Report if sensitive cookies are accessible across subdomains.

# 6. Expiry / Max-Age

- What It Does

  - Controls how long the cookie persists.

- Security Implication

  - Short-lived cookies reduce exposure.
  - Persistent cookies increase risk if stolen.

- Risk if Misused

  - Session cookies may persist across browser restarts.

- Realistic Example
  - ```
    Set-Cookie: sessionId=abc123; Max-Age=3600; Secure; HttpOnly
    ```

## Burp Suite Testing

    - Use Proxy to inspect Expires or Max-Age.
    - Restart browser and check if session persists.
    - Report misuse of persistent cookies.

# 7. Cookie Prefixes (**Secure-, **Host-)

- What They Do

  - \_\_Secure-

    - Must be set with Secure.
    - Only sent over HTTPS.

  - \_\_Host-

    - Must be:

      - Set with Secure
      - Set with Path=/
      - No Domain attribute (i.e., HostOnly: true)

- Security Implication

  - Enforces stricter rules for cookie scope and transmission.

- Risk if Missing

  - Weak cookie policy enforcement.

- Realistic Example
  - ```
    Set-Cookie: __Host-sessionId=abc123; Path=/; Secure; HttpOnly
    ```

## Burp Suite Testing

    - Use Proxy to inspect cookie names.
    - Check for missing prefixes on sensitive cookies.
    - Report if __Secure- or __Host- rules are violated.

## Mitigation Checklist

- **Recommendation**: Set cookies with
  - ```
    Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict
    ```

# Cookie Tossing

   - Send multiple cookies with the same name.
   - Observe if server logic gets confused.
