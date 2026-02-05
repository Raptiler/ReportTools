# Report Tools (Burp Suite Extension) — v1.04

A Burp Suite helper extension focused on **report-ready outputs** for security assessments.

It provides:
- quick **“missing security headers”** report generation (general + API profile),
- a **MultiSession check** workflow (compare two session contexts and replay requests),
- a one-click **copy Request/Response** formatter for reporting templates.

All outputs are copied to clipboard in a **tagged format** (e.g., `[target]...[/target]`, `[request]...[/request]`) and use `[br]` line breaks to match common reporting systems.

---

## ✨ Features

### 1) Generate Missing Headers (general)
Context menu: **Generate Missing Headers**

Checks response headers against a predefined list of common security headers:
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security`
- `Content-Security-Policy`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cache-Control`

If any are missing, it copies a report block to clipboard containing:
- target URL,
- the missing headers list,
- request headers,
- response headers (truncated with `[...]`).

---

### 2) Generate API Missing Headers (API profile)
Context menu: **Generate API Missing Headers**

Checks response headers against a smaller, API-oriented list:
- `Content-type`
- `Cache-Control`
- `Strict-Transport-Security`
- `X-Frame-Options`

Output format and clipboard behavior are the same as the general variant.

---

### 3) MultiSession Check (two-session validation + replay)
This workflow helps when you need to compare behavior across **two different authenticated sessions** and capture evidence for reporting.

#### Step-by-step
In the request editor context menu:
1. **[MultiSession] Set as first request**
2. **[MultiSession] Set as second request**
3. **[MultiSession] Execute MultiSession Check** *(appears only when both are set)*

#### What it does
- Extracts and compares:
  - `Cookie:` values (per-cookie diff)
  - `Authorization:` header (if different)
- Sends 3 requests:
  1. sends the **first request**
  2. sends the **second request**
  3. sends the **first request again** (final replay)
- Builds a single clipboard payload containing:
  - `[token1]` / `[token2]` blocks (cookie diffs)
  - `[auth_header1]` / `[auth_header2]` if Authorization differs
  - `[request1]...[response1]`
  - `[request2]...[response2]`
  - `[request3]...[response3]`

#### Chunked clipboard copy (anti-limit)
MultiSession output can be huge, so it uses **chunked clipboard copying**:
- copies up to `MULTISESSION_CHUNK_SIZE` characters per chunk (default: `9999`)
- shows progress dialogs:
  - `Skopiowano 1/7` → OK → `Skopiowano 2/7` → …

This avoids clipboard/UI limits in tools that can’t handle massive single-shot paste.

---

### 4) Copy Request/Response (report formatter)
Context menu: **Copy Request/Response**

Copies a report snippet containing:
- `[target]...[/target]`
- `[request]...[/request]` (headers + body)
- `[response]...[/response]` (headers + `[...]`)

If the response is missing, it falls back to copying only the request block.

---

## 🧱 Output formatting rules

Before copying to clipboard, the extension:
- removes any lines starting with `Sec-` (to reduce noise),
- converts line breaks into:
  - `... [br]\n`

This is tailored for report templates/editors that interpret `[br]` as a line break.

---

## 🚀 Installation

1. Burp Suite → **Extender** → **Extensions** → **Add**
2. Type: **Python**
3. Select the `.py` file (Jython 2.7)
4. Make sure Jython is configured in **Extender → Options → Python Environment**
5. Load the extension — Burp output should display:
   - `Report tool By: Paweł Zdunek - AFINE Team v1.04`

---

## ⚠️ Notes

- Missing headers checks are purely based on presence/absence of header names (case-insensitive match on header key).
- MultiSession comparisons:
  - cookie parsing assumes `Cookie: a=b; c=d` style formatting,
  - only compares cookie key/value pairs and the raw `Authorization:` header line.
- Response bodies in MultiSession are truncated if the body exceeds ~200 bytes (headers + `[...]`), to keep evidence compact.
