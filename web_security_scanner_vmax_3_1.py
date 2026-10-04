#!/usr/bin/env python3
"""
PYTHON WEB SECURITY SCANNER VMAX 3.1

Python 3.10+ | Install: python -m pip install requests dnspython
Contoh: python web_security_scanner_vmax_3_1.py https://website-anda.com --yes
Opsi: --max-pages 10 --max-links 30 --max-requests 80 --output ./reports
Laporan: HTML, JSON, TXT. --max-pages 1 --max-links 0 untuk homepage saja.
Bug checker: HTTP 404/410/5xx, asset rusak, debug error, ID duplikat,
dan form password GET/HTTP. Tidak menjalankan JS atau mengirim form.
Query string/tautan aksi umum dilewati; uji di staging bila tersedia.
Scope redirect: origin sama atau HTTP -> HTTPS host sama pada port standar.
Host kanonis berbeda (mis. www) harus dipindai langsung melalui URL akhirnya.
Skor bukan jaminan keamanan. Cakupan dan confidence tersedia di laporan.

Safe / non-intrusive web hardening checker.

Prinsip keamanan scanner ini:
  * Hanya request normal (GET/HEAD/OPTIONS) dengan jeda antar request.
  * Tidak ada payload serangan, brute force, fuzzing, atau eksploitasi.
  * Path sensitif diperiksa dengan HEAD; isi file tidak diunduh / dicetak.
  * Ada batas maksimum jumlah request (--max-requests).
  * Gunakan HANYA pada sistem milik Anda atau dengan izin tertulis pemilik.
"""
from __future__ import annotations

import argparse
import hashlib
import math
from collections import Counter, deque
from html.parser import HTMLParser
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import time
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag

import requests
import urllib3

try:  # opsional: pengecekan SPF / DMARC
    import dns.resolver
    import dns.exception
except ImportError:  # pragma: no cover
    dns = None  # type: ignore


# ============================================================
# KONFIGURASI
# ============================================================
VERSION = "VMAX 3.1"
TIMEOUT = 10
REQUEST_DELAY = 0.6
MAX_REQUESTS = 80
MAX_BODY_SAMPLE = 4096
MAX_HTML = 1_000_000
USER_AGENT = f"Python-Web-Security-Scanner/{VERSION} (Safe-Mode)"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}
SEV_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0, "PASS": 0}
SEV_CAP = {"CRITICAL": 50, "HIGH": 40, "MEDIUM": 30, "LOW": 15, "INFO": 0, "PASS": 0}
SEV_ICON = {
    "CRITICAL": "🟥", "HIGH": "🔴", "MEDIUM": "🟠",
    "LOW": "🟡", "INFO": "🔵", "PASS": "✅",
}
SEV_COLOR = {
    "CRITICAL": "#7f1d1d", "HIGH": "#b91c1c", "MEDIUM": "#c2410c",
    "LOW": "#a16207", "INFO": "#1d4ed8", "PASS": "#15803d",
}

PUBLIC_PATHS = ["robots.txt", "sitemap.xml", ".well-known/security.txt"]

# path -> (severity jika terbukti ada, tipe konten yang diharapkan)
# Diperiksa dengan HEAD saja. Isi file TIDAK diunduh.
SENSITIVE_PATHS: dict[str, tuple[str, tuple[str, ...]]] = {
    ".env": ("CRITICAL", ("text/plain", "octet-stream")),
    ".env.bak": ("CRITICAL", ("text/plain", "octet-stream")),
    ".git/HEAD": ("CRITICAL", ("text/plain", "octet-stream")),
    ".git/config": ("CRITICAL", ("text/plain", "octet-stream")),
    ".svn/entries": ("HIGH", ("text/plain", "octet-stream", "xml")),
    ".DS_Store": ("MEDIUM", ("octet-stream",)),
    ".htpasswd": ("HIGH", ("text/plain", "octet-stream")),
    "backup.zip": ("HIGH", ("zip", "octet-stream")),
    "backup.tar.gz": ("HIGH", ("gzip", "tar", "octet-stream")),
    "backup.sql": ("CRITICAL", ("sql", "text/plain", "octet-stream")),
    "db.sql": ("CRITICAL", ("sql", "text/plain", "octet-stream")),
    "dump.sql": ("CRITICAL", ("sql", "text/plain", "octet-stream")),
    "wp-config.php.bak": ("CRITICAL", ("text/plain", "octet-stream", "php")),
    "wp-config.php~": ("CRITICAL", ("text/plain", "octet-stream", "php")),
    "wp-config.php.old": ("CRITICAL", ("text/plain", "octet-stream", "php")),
    "config.php.bak": ("CRITICAL", ("text/plain", "octet-stream", "php")),
    "wp-content/debug.log": ("HIGH", ("text/plain", "octet-stream")),
    "phpinfo.php": ("HIGH", ("text/html",)),
    "server-status": ("MEDIUM", ("text/html",)),
    "phpmyadmin/": ("MEDIUM", ("text/html",)),
}

LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Runtime", "Via",
]

SECRET_PATTERNS = [
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "INFO"),
]

SESSION_NAME_RE = re.compile(r"(sess|auth|token|jwt|sid|login|csrf)", re.I)


class BudgetExceeded(Exception):
    """Batas jumlah request tercapai."""


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    confidence: str = "HIGH"
    evidence: dict | None = None
    recommendation: str | None = None


# ============================================================
# UTIL
# ============================================================
def escape_html(value) -> str:
    value = "" if value is None else str(value)
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def mask(value: str) -> str:
    return value[:4] + "…" + value[-2:] if len(value) > 8 else "***"


def html_attr(attrs: str, name: str) -> str | None:
    m = re.search(rf'\b{name}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))', attrs, re.I)
    if not m:
        return None
    return next(g for g in m.groups() if g is not None)


class PageParser(HTMLParser):
    """Parse HTML tanpa menjalankan JavaScript atau mengirim form."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.assets = []
        self.ids = []
        self.forms = []
        self.form = None
        self.base = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids.append(a["id"])
        if tag == "base" and self.base is None and a.get("href"):
            self.base = a["href"]
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag in ("img", "script", "iframe", "source", "video", "audio") and a.get("src"):
            self.assets.append(a["src"])
        if tag == "link" and "stylesheet" in (a.get("rel") or "").lower().split() and a.get("href"):
            self.assets.append(a["href"])
        if tag == "form":
            self.form = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "password": False}
            self.forms.append(self.form)
        if tag == "input" and self.form is not None and (a.get("type") or "").lower() == "password":
            self.form["password"] = True

    def handle_endtag(self, tag):
        if tag == "form":
            self.form = None


# ============================================================
# SCANNER
# ============================================================
class Scanner:
    def __init__(self, base_url: str, delay: float = REQUEST_DELAY, timeout: int = TIMEOUT,
                 max_requests: int = MAX_REQUESTS, output_dir: str | None = None,
                 skip_dns: bool = False, skip_tls: bool = False,
                 max_pages: int = 10, max_links: int = 30, insecure: bool = False):
        self.base_url = self.normalize_url(base_url)
        if not math.isfinite(delay) or delay < 0 or timeout <= 0 or max_requests <= 0:
            raise ValueError("Delay harus >=0; timeout dan max-requests harus >0.")
        if not 1 <= max_pages <= 100 or not 0 <= max_links <= 500:
            raise ValueError("max-pages harus 1–100 dan max-links 0–500.")
        self.max_pages, self.max_links = max_pages, max_links
        self.coverage = {"pages_analyzed": 0, "links_checked": 0, "skipped_links": 0}
        self.incomplete = False
        self._last_request = 0.0
        self.rate_limited = False
        self.delay = max(delay, 0.2)
        self.timeout = timeout
        self.max_requests = max_requests
        self.output_dir = output_dir
        self.skip_dns = skip_dns
        self.skip_tls = skip_tls

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "id,en;q=0.8",
        })
        self.session.max_redirects = 10
        self.verify = not insecure

        self.findings: list[Finding] = []
        self.main_response: requests.Response | None = None
        self.main_body = ""
        self.request_count = 0
        self.tls_handshakes = 0
        self.is_wordpress = False
        self.started = datetime.now()

    # ---------------------------------------------------- util
    @staticmethod
    def normalize_url(url: str) -> str:
        url = url.strip()
        m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", url)
        if m and m.group(1).lower() not in ("http", "https"):
            raise ValueError("Hanya URL http/https yang didukung.")
        if not m:
            url = "https://" + url
        if not urlparse(url).hostname:
            raise ValueError("URL tidak valid.")
        parsed = urlparse(url)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL tidak boleh berisi username/password.")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Port URL tidak valid.") from exc
        return urldefrag(url)[0]

    @property
    def final_url(self) -> str:
        return self.main_response.url if self.main_response is not None else self.base_url

    @property
    def final_host(self) -> str:
        return urlparse(self.final_url).hostname or ""

    @property
    def is_https(self) -> bool:
        return urlparse(self.final_url).scheme == "https"

    @property
    def registrable_hint(self) -> str:
        host = self.final_host
        return host[4:] if host.startswith("www.") else host

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        if self.rate_limited:
            raise BudgetExceeded("Server mengirim HTTP 429; hentikan scan dan coba lagi nanti.")
        limit = kwargs.pop("body_limit", MAX_HTML)
        follow = kwargs.pop("allow_redirects", True)
        kwargs.pop("stream", None)
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        history = []
        initial = urlparse(url)
        for hop in range(11):
            for attempt in range(2):
                if self.request_count >= self.max_requests:
                    raise BudgetExceeded(f"Batas {self.max_requests} request tercapai.")
                if self.request_count:
                    time.sleep(max(0, self.delay - (time.monotonic() - self._last_request)))
                self.request_count += 1
                self._last_request = time.monotonic()
                try:
                    r = self.session.request(method, url, stream=True, allow_redirects=False, **kwargs)
                    try:
                        # Membatasi body semua request, termasuk OPTIONS dan redirect.
                        data = bytearray()
                        if method.upper() != "HEAD":
                            for chunk in r.iter_content(16384):
                                data.extend(chunk[:limit - len(data)])
                                if len(data) >= limit:
                                    break
                        r._content = bytes(data)
                        r._content_consumed = True
                    finally:
                        r.close()
                    break
                except requests.exceptions.SSLError:
                    raise
                except (requests.ConnectionError, requests.Timeout):
                    if attempt == 1:
                        raise
            if r.status_code == 429:
                self.rate_limited = True
                self.incomplete = True
            r.history = list(history)
            if not follow or r.status_code not in (301, 302, 303, 307, 308) or not r.headers.get("Location"):
                return r
            target = urljoin(url, r.headers["Location"])
            dest = urlparse(target)
            # Redirect dibatasi host/port awal; HTTP -> HTTPS pada port standar diizinkan.
            same_origin = self.origin(target) == self.origin(url)
            upgrade = (initial.scheme == "http" and dest.scheme == "https"
                       and initial.port in (None, 80) and dest.port in (None, 443))
            if (dest.username is not None or dest.password is not None or
                    dest.hostname != initial.hostname or not (same_origin or upgrade)):
                self.emit("INFO", "Scanner", "Redirect di luar cakupan dilewati",
                          f"HTTP {r.status_code}; tujuan tidak diminta.", evidence={"url": url})
                return r
            history.append(r)
            url = target
            if r.status_code == 303 and method.upper() != "HEAD":
                method = "GET"
        raise requests.TooManyRedirects("Lebih dari 10 redirect.")

    @staticmethod
    def origin(url):
        p = urlparse(url)
        return (p.scheme.lower(), p.hostname, p.port or (443 if p.scheme == "https" else 80))

    def fetch_sample(self, url: str, **kwargs) -> tuple[requests.Response, bytes]:
        """GET tanpa redirect; hanya membaca beberapa KB pertama."""
        r = self.request("GET", url, stream=True, allow_redirects=False, body_limit=MAX_BODY_SAMPLE, **kwargs)
        try:
            sample = next(r.iter_content(MAX_BODY_SAMPLE), b"")
        finally:
            r.close()
        return r, sample

    def url_for(self, path: str) -> str:
        return urljoin(self.final_url, "/" + path.lstrip("/"))

    def emit(self, severity: str, category: str, title: str, detail: str,
             confidence: str = "HIGH", evidence: dict | None = None,
             recommendation: str | None = None) -> Finding:
        f = Finding(category, severity, title, detail, confidence, evidence, recommendation)
        self.findings.append(f)
        print(f"    {SEV_ICON.get(severity, '')} {severity:<8} {title}")
        print(f"       {detail}")
        if recommendation and severity not in ("PASS", "INFO"):
            print(f"       ➜ {recommendation}")
        return f

    # ---------------------------------------------------- 1. halaman utama
    def check_basic_info(self) -> bool:
        print("\n[+] Mengecek website utama...")
        try:
            try:
                resp = self.request("GET", self.base_url, stream=True)
            except requests.exceptions.SSLError as exc:
                self.emit("HIGH", "Transport Security", "Sertifikat TLS tidak dapat diverifikasi",
                          str(exc)[:300], "HIGH",
                          recommendation="Pasang sertifikat valid (rantai lengkap, nama host sesuai, belum kedaluwarsa).")
                self.incomplete = True
                return False

            chunks, size = [], 0
            for chunk in resp.iter_content(65536):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_HTML:
                    break
            resp.close()
            self.main_body = b"".join(chunks)[:MAX_HTML].decode(resp.encoding or "utf-8", errors="replace")
            self.main_response = resp
        except BudgetExceeded as exc:
            print(f"    ❌ {exc}")
            return False
        except requests.RequestException as exc:
            print(f"    ❌ Gagal mengakses website: {exc}")
            return False

        if not self.verify:
            self.emit("INFO", "TLS", "Verifikasi TLS dinonaktifkan oleh pengguna",
                      "Identitas server tidak terverifikasi (--insecure).")
        r = self.main_response
        print(f"    Status       : {r.status_code}")
        print(f"    Final URL    : {r.url}")
        print(f"    Server       : {r.headers.get('Server', 'Tidak diketahui')}")
        print(f"    Content-Type : {r.headers.get('Content-Type', 'Tidak diketahui')}")
        print(f"    Waktu respons: {r.elapsed.total_seconds():.2f} dtk")
        if r.history:
            chain = " -> ".join(f"{h.status_code}" for h in r.history) + f" -> {r.status_code}"
            print(f"    Redirect     : {chain}")
            if len(r.history) > 3:
                self.emit("LOW", "Transport Security", "Rantai redirect panjang",
                          f"{len(r.history)} redirect sebelum halaman akhir.", "HIGH",
                          recommendation="Persingkat redirect (idealnya maksimal 1-2 lompatan).")

        if r.status_code in (401, 403, 429):
            self.emit("INFO", "Access Control", "Scanner mendapat respons pembatasan",
                      f"Homepage memberikan HTTP {r.status_code}. Hasil dapat berbeda dari browser normal "
                      "(WAF / rate limit).", "HIGH",
                      {"status": r.status_code, "final_url": r.url})
        elif r.status_code >= 500:
            self.emit("MEDIUM", "Availability", "Server mengembalikan error",
                      f"Homepage memberikan HTTP {r.status_code}; hasil scan mungkin tidak representatif.", "HIGH")
        if not 200 <= r.status_code < 300:
            self.incomplete = True
        return True

    # ---------------------------------------------------- 2. HTTPS
    def check_https(self):
        print("\n[+] Mengecek HTTPS...")
        if self.is_https:
            self.emit("PASS", "Transport Security", "HTTPS aktif", f"Final URL menggunakan HTTPS: {self.final_url}")
        else:
            self.emit("MEDIUM", "Transport Security", "HTTPS tidak aktif",
                      f"Final URL masih HTTP: {self.final_url}",
                      recommendation="Aktifkan HTTPS dan arahkan seluruh HTTP ke HTTPS.")

        base = urlparse(self.base_url)
        if base.port not in (None, 80, 443):
            return
        http_url = f"http://{base.hostname}/"
        try:
            r = self.request("GET", http_url, allow_redirects=False, stream=True)
            r.close()
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
                self.emit("PASS", "Transport Security", "HTTP diarahkan ke HTTPS", f"HTTP {r.status_code} -> {loc}")
            elif r.status_code in (301, 302, 307, 308):
                self.emit("INFO", "Transport Security", "Redirect HTTP perlu diverifikasi",
                          f"HTTP {r.status_code}; Location={loc or '-'}", "MEDIUM")
            else:
                self.emit("MEDIUM", "Transport Security", "HTTP tidak diarahkan ke HTTPS",
                          f"Port 80 memberikan HTTP {r.status_code} tanpa redirect.", "MEDIUM",
                          recommendation="Tambahkan redirect 301 dari HTTP ke HTTPS.")
        except BudgetExceeded:
            raise
        except requests.RequestException:
            self.emit("INFO", "Transport Security", "Port 80 tidak dapat dijangkau",
                      "Tidak ada respons HTTP pada port 80 (bisa normal bila hanya HTTPS).", "LOW")

    # ---------------------------------------------------- 3. TLS
    def _accepts_legacy(self, host: str, port: int, version) -> bool | None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = version
                ctx.maximum_version = version
            except (ValueError, ssl.SSLError):
                return None
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            try:
                self.tls_handshakes += 1
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        return True
            except (ssl.SSLError, OSError):
                return False

    def check_tls(self):
        if self.skip_tls or not self.is_https:
            return
        print("\n[+] Mengecek TLS / sertifikat...")
        host = self.final_host
        port = urlparse(self.final_url).port or 443
        try:
            self.tls_handshakes += 1
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = tls.version()
                    cipher = tls.cipher()
        except ssl.SSLCertVerificationError as exc:
            self.emit("HIGH", "TLS", "Verifikasi sertifikat gagal", str(exc)[:300], "HIGH",
                      recommendation="Perbaiki sertifikat / rantai intermediate / nama host.")
            return
        except (ssl.SSLError, OSError) as exc:
            self.emit("INFO", "TLS", "Pengecekan TLS tidak dapat dilakukan", str(exc)[:200], "LOW")
            return

        if version in ("TLSv1.3", "TLSv1.2"):
            self.emit("PASS", "TLS", f"Protokol {version}", f"Cipher: {cipher[0] if cipher else '-'}")
        else:
            self.emit("MEDIUM", "TLS", f"Protokol usang dinegosiasikan: {version}", "Klien modern seharusnya TLS 1.2+.",
                      recommendation="Nonaktifkan protokol di bawah TLS 1.2.")

        try:
            not_after = ssl.cert_time_to_seconds(cert["notAfter"])
            days = int((not_after - time.time()) // 86400)
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            issuer_name = issuer.get("organizationName") or issuer.get("commonName") or "-"
            ev = {"days_left": days, "issuer": issuer_name}
            if days < 0:
                self.emit("HIGH", "TLS", "Sertifikat sudah kedaluwarsa", f"Kedaluwarsa {-days} hari lalu.", "HIGH", ev,
                          "Perbarui sertifikat segera.")
            elif days < 14:
                self.emit("MEDIUM", "TLS", "Sertifikat hampir kedaluwarsa", f"Sisa {days} hari.", "HIGH", ev,
                          "Perbarui sertifikat / pastikan auto-renew berjalan.")
            elif days < 30:
                self.emit("LOW", "TLS", "Sertifikat akan segera kedaluwarsa", f"Sisa {days} hari.", "HIGH", ev,
                          "Pastikan auto-renew berjalan.")
            else:
                self.emit("PASS", "TLS", "Masa berlaku sertifikat", f"Sisa {days} hari; penerbit: {issuer_name}.",
                          "HIGH", ev)
        except (KeyError, ValueError):
            pass

        legacy = []
        unknown = False
        for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            res = self._accepts_legacy(host, port, ver)
            if res is None:
                unknown = True
            elif res:
                legacy.append(name)
        if legacy:
            self.emit("MEDIUM", "TLS", "Server menerima protokol usang", ", ".join(legacy) + " diterima.", "HIGH",
                      {"protocols": legacy}, "Nonaktifkan TLS 1.0 dan 1.1.")
        elif unknown:
            self.emit("INFO", "TLS", "TLS 1.0/1.1 tidak dapat diuji dari klien ini",
                      "OpenSSL lokal menolak protokol lama; gunakan alat seperti SSL Labs.", "LOW")
        else:
            self.emit("PASS", "TLS", "TLS 1.0/1.1 ditolak", "Server tidak menerima protokol usang.")

    # ---------------------------------------------------- 4. header
    def check_security_headers(self):
        print("\n[+] Mengecek security headers...")
        h = self.main_response.headers

        # HSTS
        if self.is_https:
            hsts = h.get("Strict-Transport-Security")
            if not hsts:
                self.emit("MEDIUM", "Security Header", "Strict-Transport-Security tidak ditemukan",
                          "Membantu mencegah HTTPS downgrade / SSL stripping.", "HIGH", {"header": "Strict-Transport-Security"},
                          "Tambahkan: Strict-Transport-Security: max-age=31536000; includeSubDomains")
            else:
                m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                age = int(m.group(1)) if m else 0
                if age <= 0:
                    self.emit("MEDIUM", "Security Header", "HSTS max-age tidak valid / 0", f"Nilai: {hsts}",
                              recommendation="Gunakan max-age minimal 31536000.")
                elif age < 15552000:
                    self.emit("LOW", "Security Header", "HSTS max-age terlalu pendek", f"max-age={age} (<180 hari).",
                              recommendation="Naikkan max-age ke 31536000 (1 tahun).")
                else:
                    self.emit("PASS", "Security Header", "Strict-Transport-Security ditemukan", f"Nilai: {hsts}")
                if "includesubdomains" not in hsts.lower():
                    self.emit("INFO", "Security Header", "HSTS tanpa includeSubDomains",
                              "Subdomain belum otomatis dilindungi HSTS.", "HIGH")

        # CSP
        csp = h.get("Content-Security-Policy")
        csp_ro = h.get("Content-Security-Policy-Report-Only")
        if csp:
            self.emit("PASS", "Security Header", "Content-Security-Policy ditemukan", f"Nilai: {csp[:300]}")
            self.analyze_csp(csp)
        elif csp_ro:
            self.emit("LOW", "Security Header", "CSP hanya dalam mode Report-Only",
                      "Kebijakan tidak ditegakkan, hanya dilaporkan.", "HIGH",
                      recommendation="Setelah tahap uji, aktifkan Content-Security-Policy.")
        else:
            self.emit("LOW", "Security Header", "Content-Security-Policy tidak ditemukan",
                      "Membantu membatasi dampak XSS dan pemuatan resource tak diizinkan.", "HIGH",
                      {"header": "Content-Security-Policy"}, "Tambahkan CSP yang ketat sesuai aplikasi.")

        # X-Content-Type-Options
        xcto = h.get("X-Content-Type-Options")
        if xcto and xcto.strip().lower() == "nosniff":
            self.emit("PASS", "Security Header", "X-Content-Type-Options ditemukan", f"Nilai: {xcto}")
        else:
            self.emit("LOW", "Security Header", "X-Content-Type-Options tidak benar / tidak ada",
                      f"Nilai: {xcto or '-'}", "HIGH", {"header": "X-Content-Type-Options"},
                      "Tambahkan: X-Content-Type-Options: nosniff")

        # Framing
        xfo = h.get("X-Frame-Options")
        csp_fa = "frame-ancestors" in (csp or "").lower()
        if xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
            self.emit("PASS", "Security Header", "X-Frame-Options ditemukan", f"Nilai: {xfo}")
        elif csp_fa:
            self.emit("PASS", "Security Header", "Proteksi framing via CSP frame-ancestors", "frame-ancestors tersedia.")
        elif xfo:
            self.emit("LOW", "Security Header", "X-Frame-Options bernilai tidak standar", f"Nilai: {xfo}",
                      recommendation="Gunakan DENY / SAMEORIGIN atau CSP frame-ancestors.")
        else:
            self.emit("LOW", "Security Header", "Proteksi clickjacking tidak ditemukan",
                      "Tidak ada X-Frame-Options maupun CSP frame-ancestors.", "HIGH",
                      {"header": "X-Frame-Options"}, "Tambahkan X-Frame-Options: SAMEORIGIN atau frame-ancestors.")

        # Referrer-Policy
        rp = h.get("Referrer-Policy")
        if not rp:
            self.emit("LOW", "Security Header", "Referrer-Policy tidak ditemukan",
                      "Mengontrol informasi referrer yang dikirim browser.", "HIGH", {"header": "Referrer-Policy"},
                      "Tambahkan: Referrer-Policy: strict-origin-when-cross-origin")
        elif rp.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            self.emit("LOW", "Security Header", "Referrer-Policy terlalu longgar", f"Nilai: {rp}",
                      recommendation="Gunakan strict-origin-when-cross-origin atau lebih ketat.")
        else:
            self.emit("PASS", "Security Header", "Referrer-Policy ditemukan", f"Nilai: {rp}")

        # Permissions-Policy
        pp = h.get("Permissions-Policy")
        if pp:
            self.emit("PASS", "Security Header", "Permissions-Policy ditemukan", f"Nilai: {pp[:200]}")
        else:
            self.emit("LOW", "Security Header", "Permissions-Policy tidak ditemukan",
                      "Membatasi fitur browser tertentu.", "HIGH", {"header": "Permissions-Policy"},
                      "Contoh: Permissions-Policy: camera=(), microphone=(), geolocation=()")

        # Cross-origin isolation (opsional)
        missing = [x for x in ("Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy") if x not in h]
        if missing:
            self.emit("INFO", "Security Header", "Header isolasi cross-origin tidak ada (opsional)",
                      ", ".join(missing), "HIGH", {"headers": missing})

        xxp = h.get("X-XSS-Protection")
        if xxp and xxp.strip().startswith("1"):
            self.emit("INFO", "Security Header", "X-XSS-Protection aktif (usang)",
                      f"Nilai: {xxp}. Filter ini sudah dihapus dari browser modern.", "HIGH",
                      recommendation="Gunakan CSP; set X-XSS-Protection: 0 bila perlu.")

    def analyze_csp(self, csp: str):
        d = parse_csp(csp)
        script = d.get("script-src", d.get("default-src"))
        src_name = "script-src" if "script-src" in d else "default-src"
        issues = 0

        if script is None:
            self.emit("MEDIUM", "CSP", "CSP tidak membatasi script",
                      "Tidak ada script-src maupun default-src.", "HIGH",
                      recommendation="Definisikan script-src / default-src yang ketat.")
            issues += 1
        else:
            has_nonce = any(t.startswith("'nonce-") or t.startswith("'sha") for t in script)
            if "'unsafe-inline'" in script and not has_nonce:
                self.emit("MEDIUM", "CSP", "CSP mengizinkan 'unsafe-inline' pada script",
                          f"{src_name} memuat 'unsafe-inline' tanpa nonce/hash, sehingga XSS inline tidak terblokir.",
                          "HIGH", {"directive": src_name},
                          "Pindahkan script inline ke file eksternal atau gunakan nonce/hash.")
                issues += 1
            if "'unsafe-eval'" in script:
                self.emit("LOW", "CSP", "CSP mengizinkan 'unsafe-eval'",
                          f"{src_name} memuat 'unsafe-eval' (eval/new Function diizinkan).", "HIGH",
                          {"directive": src_name}, "Hapus 'unsafe-eval' jika tema/plugin tidak membutuhkannya.")
                issues += 1
            if "*" in script or "http:" in script:
                self.emit("MEDIUM", "CSP", "CSP mengizinkan sumber script terlalu luas",
                          f"{src_name} berisi wildcard atau http:.", "HIGH", {"directive": src_name},
                          "Batasi ke host yang benar-benar dipakai.")
                issues += 1
            if "data:" in script:
                self.emit("MEDIUM", "CSP", "CSP mengizinkan data: pada script",
                          f"{src_name} memuat data:, yang dapat dipakai menyuntik script.", "HIGH",
                          {"directive": src_name}, "Hapus data: dari script-src/default-src (batasi ke img-src/font-src).")
                issues += 1
            if "https:" in script and "'strict-dynamic'" not in script:
                self.emit("LOW", "CSP", "CSP mengizinkan script dari host HTTPS mana pun",
                          f"{src_name} memuat skema https: (tanpa daftar host).", "HIGH", {"directive": src_name},
                          "Daftarkan host spesifik atau gunakan nonce + 'strict-dynamic'.")
                issues += 1

        obj = d.get("object-src", d.get("default-src"))
        if obj is None or "'none'" not in obj:
            self.emit("LOW", "CSP", "object-src tidak dibatasi", "Disarankan object-src 'none'.", "HIGH",
                      recommendation="Tambahkan: object-src 'none'")
            issues += 1
        if "base-uri" not in d:
            self.emit("LOW", "CSP", "base-uri tidak ada",
                      "Tanpa base-uri, injeksi <base> dapat membelokkan URL relatif.", "HIGH",
                      recommendation="Tambahkan: base-uri 'self'")
            issues += 1
        if "frame-ancestors" not in d:
            self.emit("INFO", "CSP", "CSP tanpa frame-ancestors",
                      "Proteksi framing bergantung pada X-Frame-Options.", "HIGH")
        if issues == 0:
            self.emit("PASS", "CSP", "CSP tidak memiliki konfigurasi lemah umum", "Tidak ada pola lemah yang terdeteksi.")

    # ---------------------------------------------------- 5. cookie
    def collect_set_cookies(self) -> list[str]:
        out: list[str] = []
        for r in list(self.main_response.history) + [self.main_response]:
            hdrs = getattr(getattr(r, "raw", None), "headers", None)
            if hdrs is not None and hasattr(hdrs, "getlist"):
                out.extend(hdrs.getlist("Set-Cookie"))
            elif "Set-Cookie" in r.headers:
                out.append(r.headers["Set-Cookie"])
        return out

    def check_cookies(self):
        print("\n[+] Mengecek cookie...")
        cookies = self.collect_set_cookies()
        if not cookies:
            self.emit("INFO", "Cookie", "Tidak ada Set-Cookie pada response utama",
                      "Tidak ada cookie yang dapat dievaluasi dari response utama.")
            return
        for raw in cookies:
            parts = [p.strip() for p in raw.split(";")]
            name = parts[0].split("=", 1)[0] if parts else "?"
            attrs = {}
            for p in parts[1:]:
                k, _, v = p.partition("=")
                attrs[k.strip().lower()] = v.strip().lower()
            sensitive = bool(SESSION_NAME_RE.search(name))
            problems, sev = [], "PASS"

            def bump(new):
                nonlocal sev
                if SEV_ORDER[new] < SEV_ORDER[sev]:
                    sev = new

            if self.is_https and "secure" not in attrs:
                problems.append("tanpa Secure"); bump("MEDIUM" if sensitive else "LOW")
            if "httponly" not in attrs:
                problems.append("tanpa HttpOnly"); bump("MEDIUM" if sensitive else "LOW")
            if "samesite" not in attrs:
                problems.append("tanpa SameSite"); bump("LOW")
            elif attrs["samesite"] == "none" and "secure" not in attrs:
                problems.append("SameSite=None tanpa Secure"); bump("MEDIUM")
            if name.startswith("__Host-") and ("secure" not in attrs or attrs.get("path") != "/" or "domain" in attrs):
                problems.append("prefix __Host- tidak dipenuhi"); bump("LOW")

            if problems:
                self.emit(sev, "Cookie", f"Cookie '{name}': " + ", ".join(problems),
                          "Atribut keamanan tidak lengkap pada Set-Cookie.", "MEDIUM",
                          {"cookie": name, "attributes": sorted(attrs)},
                          "Tambahkan Secure; HttpOnly; SameSite=Lax/Strict pada cookie yang relevan.")
            else:
                self.emit("PASS", "Cookie", f"Cookie '{name}' memiliki atribut keamanan lengkap",
                          "Secure/HttpOnly/SameSite terdeteksi.", "MEDIUM")

    # ---------------------------------------------------- 6. CORS & metode
    def check_cors(self):
        print("\n[+] Mengecek CORS...")
        origin = "https://scanner-origin.invalid"
        r = self.request("GET", self.final_url, headers={"Origin": origin}, stream=True, allow_redirects=False)
        r.close()
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        ev = {"acao": acao, "credentials": acac}
        if not acao:
            self.emit("PASS", "CORS", "Tidak ada header CORS permisif", "Access-Control-Allow-Origin tidak dikirim.")
        elif acao == origin and acac:
            self.emit("HIGH", "CORS", "CORS memantulkan Origin dengan credentials",
                      "Origin asing diterima bersama Allow-Credentials: true.", "MEDIUM", ev,
                      "Verifikasi dampak pada endpoint terautentikasi; gunakan allowlist origin.")
        elif acao == origin:
            self.emit("MEDIUM", "CORS", "CORS memantulkan sembarang Origin",
                      "Origin asing diterima tanpa allowlist.", "MEDIUM", ev, "Gunakan allowlist origin.")
        elif acao == "*":
            self.emit("INFO", "CORS", "CORS wildcard (*)",
                      "Respons publik dapat dibaca lintas origin tanpa credentials. "
                      "Browser menolak kombinasi wildcard dengan request ber-credentials.", "HIGH", ev,
                      "Batasi bila endpoint memuat data non-publik.")
        else:
            self.emit("PASS", "CORS", "CORS dibatasi", f"Allow-Origin: {acao}", "HIGH", ev)

    def check_http_methods(self):
        print("\n[+] Mengecek metode HTTP...")
        r = self.request("OPTIONS", self.final_url, allow_redirects=False)
        r.close()
        allow = r.headers.get("Allow") or r.headers.get("Access-Control-Allow-Methods")
        if not allow:
            self.emit("INFO", "HTTP Methods", "Server tidak mengumumkan metode (Allow)",
                      f"OPTIONS -> HTTP {r.status_code}", "MEDIUM")
            return
        methods = {m.strip().upper() for m in allow.split(",")}
        risky = sorted(methods & {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"})
        if risky:
            sev = "MEDIUM" if {"TRACE", "TRACK"} & set(risky) else "LOW"
            self.emit(sev, "HTTP Methods", "Metode berisiko diumumkan: " + ", ".join(risky),
                      f"Allow: {allow}", "MEDIUM", {"allow": sorted(methods)},
                      "Nonaktifkan metode yang tidak dipakai.")
        else:
            self.emit("PASS", "HTTP Methods", "Metode HTTP wajar", f"Allow: {allow}")

    # ---------------------------------------------------- 7. isi HTML
    def check_html_content(self):
        print("\n[+] Menganalisis isi HTML...")
        body = self.main_body
        if not body:
            self.emit("INFO", "Content", "Tidak ada isi HTML untuk dianalisis", "-", "LOW")
            return
        low = body.lower()

        # WordPress / generator
        gen = None
        for pat in (r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']'):
            m = re.search(pat, body, re.I)
            if m:
                gen = m.group(1)
                break
        self.is_wordpress = ("wp-content/" in low or "wp-includes/" in low
                             or bool(gen and "wordpress" in gen.lower()))
        if gen:
            has_ver = bool(re.search(r"\d+\.\d+", gen))
            self.emit("LOW" if has_ver else "INFO", "Information Disclosure",
                      f"Meta generator terlihat: {gen}", "Mengungkap teknologi/versi CMS.", "HIGH",
                      {"generator": gen}, "Hapus meta generator (mis. remove_action('wp_head','wp_generator')).")
        if self.is_wordpress:
            self.emit("INFO", "Fingerprint", "Situs terdeteksi memakai WordPress",
                      "Pastikan inti WordPress, tema, dan plugin selalu diperbarui.", "HIGH")

        # tag
        mixed_active, mixed_passive, no_sri = [], [], set()
        form_http = 0
        site = self.registrable_hint
        for i, m in enumerate(re.finditer(r"<(script|img|iframe|link|source|video|audio|embed|object|form)\b([^>]*)>",
                                          body, re.I | re.S)):
            if i > 6000:
                break
            tag, attrs = m.group(1).lower(), m.group(2)
            if tag == "form":
                action = html_attr(attrs, "action") or ""
                if action.lower().startswith("http://") and self.is_https:
                    form_http += 1
                continue
            url = html_attr(attrs, "href" if tag == "link" else "data" if tag == "object" else "src")
            if not url:
                continue
            if tag == "link" and "stylesheet" not in (html_attr(attrs, "rel") or "").lower():
                continue
            if url.lower().startswith("http://") and self.is_https:
                (mixed_active if tag in ("script", "iframe", "embed", "object", "link") else mixed_passive).append(url)
            if tag == "script" and url.lower().startswith(("http://", "https://", "//")):
                host = urlparse(url if not url.startswith("//") else "https:" + url).hostname or ""
                if host and not (host == site or host.endswith("." + site)) and not html_attr(attrs, "integrity"):
                    no_sri.add(host)

        if mixed_active:
            self.emit("MEDIUM", "Content", "Mixed content aktif (script/iframe/css via HTTP)",
                      f"{len(mixed_active)} resource aktif dimuat lewat HTTP.", "HIGH",
                      {"examples": mixed_active[:3]}, "Muat semua resource via HTTPS.")
        if mixed_passive:
            self.emit("LOW", "Content", "Mixed content pasif (gambar/media via HTTP)",
                      f"{len(mixed_passive)} resource pasif dimuat lewat HTTP.", "HIGH",
                      {"examples": mixed_passive[:3]}, "Muat semua resource via HTTPS.")
        if not (mixed_active or mixed_passive) and self.is_https:
            self.emit("PASS", "Content", "Tidak ada mixed content terdeteksi", "Resource pada HTML utama memakai HTTPS.")
        if form_http:
            self.emit("MEDIUM", "Content", "Form mengirim data lewat HTTP",
                      f"{form_http} form dengan action http://.", "HIGH", recommendation="Gunakan action HTTPS.")
        if not self.is_https and 'type="password"' in low.replace("'", '"'):
            self.emit("HIGH", "Content", "Form password pada halaman HTTP",
                      "Kredensial dapat disadap di jaringan.", "HIGH", recommendation="Layani halaman login via HTTPS.")
        if no_sri:
            hosts = sorted(no_sri)
            self.emit("LOW", "Content", "Script pihak ketiga tanpa Subresource Integrity",
                      f"{len(hosts)} host eksternal: {', '.join(hosts[:5])}", "MEDIUM", {"hosts": hosts[:10]},
                      "Tambahkan atribut integrity + crossorigin untuk script CDN yang statis.")

        # komentar HTML
        words = set()
        for c in re.findall(r"<!--(.*?)-->", body, re.S):
            if c.lstrip().startswith("[if"):
                continue
            words.update(w.lower() for w in re.findall(r"(password|passwd|secret|api[_-]?key|todo|fixme|debug)", c, re.I))
        if words:
            self.emit("INFO", "Content", "Komentar HTML memuat kata sensitif",
                      "Kata kunci: " + ", ".join(sorted(words)) + " (isi tidak ditampilkan).", "LOW",
                      recommendation="Tinjau dan hapus komentar yang tidak perlu dari produksi.")

        # secret
        for label, pat, sev in SECRET_PATTERNS:
            found = pat.findall(body)
            if found:
                note = ("Kunci ini sering sengaja publik; pastikan dibatasi (referrer/API restriction)."
                        if sev == "INFO" else "Segera cabut dan ganti kredensial ini.")
                self.emit(sev, "Content", f"Potensi {label} pada HTML publik",
                          f"{len(found)} kecocokan (contoh tersamar: {mask(found[0])}).", "MEDIUM",
                          {"count": len(found)}, note)

    def check_information_disclosure(self):
        print("\n[+] Mengecek informasi server...")
        h = self.main_response.headers
        found = False
        for name in LEAK_HEADERS:
            val = h.get(name)
            if not val:
                continue
            found = True
            versioned = bool(re.search(r"\d+\.\d+", val))
            self.emit("LOW" if versioned else "INFO", "Information Disclosure",
                      f"{name} terlihat", f"{name}: {val}", "HIGH", {"header": name, "value": val},
                      "Sembunyikan versi/detail teknologi (mis. server_tokens off; expose_php=Off).")
        if not found:
            self.emit("PASS", "Information Disclosure", "Header fingerprinting umum tidak ditemukan",
                      "Server tidak mengungkap header teknologi yang diperiksa.")

    # ---------------------------------------------------- 8. path
    @staticmethod
    def signature(r: requests.Response, sample: bytes) -> dict:
        return {
            "status": r.status_code,
            "content_type": (r.headers.get("Content-Type") or "").split(";")[0].strip().lower(),
            "content_length": r.headers.get("Content-Length"),
            "location": r.headers.get("Location"),
            "sample_hash": hashlib.sha256(sample).hexdigest() if sample else None,
        }

    def build_baseline(self) -> dict | None:
        token = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        try:
            r = self.request("HEAD", self.url_for(f"scanner-baseline-{token}.txt"), allow_redirects=False)
            return self.signature(r, b"")
        except requests.RequestException:
            return None

    def check_common_paths(self):
        print("\n[+] Mengecek path publik dan indikasi file sensitif...")
        baseline = self.build_baseline()
        if baseline:
            print(f"    Baseline URL acak -> HTTP {baseline['status']} ({baseline['content_type'] or 'unknown'})")

        for path in PUBLIC_PATHS:
            try:
                r = self.request("GET", self.url_for(path), allow_redirects=False, stream=True)
                r.close()
                ev = {"status": r.status_code, "location": r.headers.get("Location")}
                if path.endswith("security.txt"):
                    if r.status_code == 200:
                        self.emit("PASS", "Public Path", path, "security.txt tersedia (kanal pelaporan celah).", "HIGH", ev)
                    else:
                        self.emit("INFO", "Public Path", path, f"HTTP {r.status_code} - belum ada security.txt.", "HIGH", ev,
                                  "Sediakan /.well-known/security.txt agar peneliti tahu cara melapor (RFC 9116).")
                else:
                    self.emit("INFO", "Public Path", path, f"{path} -> HTTP {r.status_code}", "HIGH", ev)
            except requests.RequestException as exc:
                self.emit("INFO", "Public Path", path, f"Tidak dapat diperiksa: {exc}", "LOW")

        for path, (base_sev, expected) in SENSITIVE_PATHS.items():
            try:
                r = self.request("HEAD", self.url_for(path), allow_redirects=False)
            except requests.RequestException as exc:
                self.emit("INFO", "Sensitive Path", path, f"Tidak dapat diperiksa: {exc}", "LOW")
                continue
            st = r.status_code
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            ev = {"method": "HEAD", "status": st, "content_type": ct or None,
                  "content_length": r.headers.get("Content-Length"), "location": r.headers.get("Location")}

            if st == 200:
                bl200 = bool(baseline and baseline["status"] == 200)
                cl, bcl = r.headers.get("Content-Length"), baseline.get("content_length") if baseline else None
                similar = bl200 and ct == baseline["content_type"] and (not cl or not bcl or cl == bcl)
                if similar:
                    self.emit("INFO", "Sensitive Path", path,
                              "HTTP 200 namun mirip halaman 'tidak ditemukan' kustom (soft-404).", "LOW", ev)
                elif any(x in ct for x in expected):
                    self.emit(base_sev, "Sensitive Path", f"Potensi exposure: {path}",
                              f"{path} merespons HTTP 200 dengan tipe konten sesuai ({ct or '-'}). Isi tidak diunduh.",
                              "LOW" if bl200 else "MEDIUM", ev,
                              "Verifikasi hanya oleh administrator yang berwenang; blokir akses dan rotasi kredensial bila terbukti.")
                elif "text/html" in ct:
                    self.emit("MEDIUM", "Sensitive Path", f"Perlu verifikasi manual: {path}",
                              "HTTP 200 berupa HTML (bisa halaman kustom).", "LOW", ev,
                              "Periksa oleh administrator apakah file benar-benar ada.")
                else:
                    self.emit(base_sev, "Sensitive Path", f"Potensi exposure: {path}",
                              f"HTTP 200 (tipe {ct or 'tidak diketahui'}). Isi tidak diunduh.", "MEDIUM", ev,
                              "Verifikasi oleh administrator yang berwenang.")
            elif st in (301, 302, 307, 308):
                self.emit("INFO", "Sensitive Path", path, f"Redirect HTTP {st}.", "HIGH", ev)
            elif st == 401:
                self.emit("INFO", "Sensitive Path", path, "Meminta autentikasi (HTTP 401) - path kemungkinan ada.", "MEDIUM", ev)
            elif st == 403:
                self.emit("PASS", "Sensitive Path", path, "Akses ditolak (HTTP 403).", "HIGH", ev)
            elif st == 404:
                self.emit("PASS", "Sensitive Path", path, "Tidak ditemukan (HTTP 404).", "HIGH", ev)
            elif st in (405, 501):
                self.emit("INFO", "Sensitive Path", path, f"HEAD tidak didukung (HTTP {st}); tidak dapat diverifikasi.", "LOW", ev)
            else:
                self.emit("INFO", "Sensitive Path", path, f"HTTP {st}.", "MEDIUM", ev)

    # ---------------------------------------------------- 9. WordPress
    def check_wordpress(self):
        if not self.is_wordpress:
            return
        print("\n[+] Mengecek hardening WordPress (pasif)...")

        def head(path):
            return self.request("HEAD", self.url_for(path), allow_redirects=False)

        try:
            if head("readme.html").status_code == 200:
                self.emit("LOW", "WordPress", "readme.html dapat diakses",
                          "File ini dapat mengungkap versi WordPress.", "MEDIUM",
                          recommendation="Hapus atau blokir readme.html.")
            else:
                self.emit("PASS", "WordPress", "readme.html tidak terbuka", "-")

            r, sample = self.fetch_sample(self.url_for("xmlrpc.php"))
            if r.status_code == 405 or (r.status_code == 200 and b"XML-RPC server accepts POST" in sample):
                self.emit("LOW", "WordPress", "xmlrpc.php aktif",
                          "Endpoint ini kerap disalahgunakan untuk brute force / pingback.", "HIGH",
                          {"status": r.status_code}, "Nonaktifkan XML-RPC bila tidak dipakai.")
            else:
                self.emit("PASS", "WordPress", "xmlrpc.php tidak aktif", f"HTTP {r.status_code}.")

            r, sample = self.fetch_sample(self.url_for("wp-json/wp/v2/users"))
            if r.status_code == 200 and sample.lstrip().startswith(b"["):
                self.emit("LOW", "WordPress", "REST API membuka daftar pengguna",
                          "Username dapat dienumerasi lewat /wp-json/wp/v2/users (nama tidak ditampilkan di laporan).",
                          "HIGH", recommendation="Batasi endpoint users bagi pengguna belum login.")
            else:
                self.emit("PASS", "WordPress", "Daftar pengguna REST API tidak terbuka", f"HTTP {r.status_code}.")

            r, sample = self.fetch_sample(self.url_for("wp-content/uploads/"))
            if r.status_code == 200 and b"Index of" in sample:
                self.emit("MEDIUM", "WordPress", "Directory listing aktif di wp-content/uploads/",
                          "Daftar file unggahan dapat dilihat publik.", "HIGH",
                          recommendation="Nonaktifkan autoindex / Options -Indexes.")
            else:
                self.emit("PASS", "WordPress", "Directory listing uploads tidak aktif", f"HTTP {r.status_code}.")

            if head("wp-login.php").status_code == 200:
                self.emit("INFO", "WordPress", "Halaman wp-login.php dapat diakses publik",
                          "Pertimbangkan 2FA, rate limiting, atau pembatasan IP untuk login admin.", "HIGH")
        except requests.RequestException as exc:
            self.emit("INFO", "WordPress", "Sebagian pengecekan WordPress gagal", str(exc)[:200], "LOW")

    # ---------------------------------------------------- 10. SPF / DMARC
    def check_email_auth(self):
        if self.skip_dns:
            return
        print("\n[+] Mengecek autentikasi email domain (SPF/DMARC)...")
        domain = self.registrable_hint
        try:
            ipaddress.ip_address(domain)
            return
        except ValueError:
            pass
        if dns is None:
            self.emit("INFO", "Email Security", "Pengecekan SPF/DMARC dilewati",
                      "Modul dnspython belum terpasang (pip install dnspython).", "HIGH")
            return

        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout

        def txt(name):
            try:
                ans = resolver.resolve(name, "TXT")
                return ["".join(s.decode("utf-8", "replace") for s in rr.strings) for rr in ans]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except dns.exception.DNSException:
                return None

        spf_raw, dmarc_raw = txt(domain), txt(f"_dmarc.{domain}")
        if spf_raw is None or dmarc_raw is None:
            self.emit("INFO", "Email Security", "Query DNS gagal", f"Tidak dapat membaca TXT untuk {domain}.", "LOW")
            return
        spf = next((r for r in spf_raw if r.lower().startswith("v=spf1")), None)
        dmarc = next((r for r in dmarc_raw if r.lower().startswith("v=dmarc1")), None)

        if not spf and not dmarc:
            self.emit("INFO", "Email Security", "SPF dan DMARC tidak ditemukan pada host yang diuji",
                      f"Host: {domain}. Domain email dan kebijakan DMARC induk belum diperiksa.", "MEDIUM",
                      recommendation="Pasang SPF dan DMARC (mulai p=none lalu naikkan ke quarantine/reject).")
            return
        if not spf:
            self.emit("LOW", "Email Security", "SPF tidak ada", f"Tidak ada record v=spf1 untuk {domain}.", "HIGH",
                      recommendation="Tambahkan record SPF.")
        elif re.search(r"[+?]all\b", spf) or spf.rstrip().endswith(" all"):
            self.emit("MEDIUM", "Email Security", "SPF terlalu longgar", f"Record: {spf[:200]}", "HIGH",
                      recommendation="Akhiri SPF dengan -all atau ~all.")
        else:
            self.emit("PASS", "Email Security", "SPF ditemukan", f"Record: {spf[:200]}")
        if not dmarc:
            self.emit("LOW", "Email Security", "DMARC tidak ada", f"Tidak ada _dmarc.{domain}.", "HIGH",
                      recommendation="Tambahkan DMARC dengan alamat rua= untuk laporan.")
        else:
            m = re.search(r"\bp\s*=\s*(\w+)", dmarc, re.I)
            policy = m.group(1).lower() if m else "?"
            if policy == "none":
                self.emit("LOW", "Email Security", "DMARC hanya monitoring (p=none)", f"Record: {dmarc[:200]}", "HIGH",
                          recommendation="Naikkan bertahap ke p=quarantine lalu p=reject.")
            elif policy in ("quarantine", "reject"):
                self.emit("PASS", "Email Security", f"DMARC ditemukan (p={policy})", f"Record: {dmarc[:200]}")
            else:
                self.emit("LOW", "Email Security", "Kebijakan DMARC tidak valid", f"p={policy}")

    # ---------------------------------------------------- bug HTML/HTTP
    def analyze_page(self, url: str, body: str) -> PageParser:
        page = PageParser()
        page.feed(body)
        self.coverage["pages_analyzed"] += 1
        duplicates = [key for key, n in Counter(page.ids).items() if n > 1]
        if duplicates:
            self.emit("LOW", "Website Bug", "ID HTML duplikat", "ID yang sama dapat mengganggu label, navigasi, dan JavaScript.",
                      evidence={"url": url, "ids": duplicates[:20]},
                      recommendation="Gunakan ID unik pada setiap elemen.")
        errors = {
            "Python traceback": r"Traceback \(most recent call last\):",
            "PHP fatal error": r"(?:Fatal error|Uncaught [A-Za-z\\]+Exception):.{0,300}\bon line\b",
            "ASP.NET debug error": r"Server Error in ['\"]/.*?Application",
            "Database exception": r"(?:SQLSTATE\[[A-Z0-9]+\]|mysql_fetch_array\(\).*?(?:expects|error))",
        }
        for label, pattern in errors.items():
            if re.search(pattern, body, re.I | re.S):
                self.emit("MEDIUM", "Website Bug", "Indikasi pesan error aplikasi",
                          f"Pola {label} terlihat; bisa juga berupa contoh kode/dokumentasi.", "MEDIUM",
                          {"url": url, "pattern": label},
                          "Periksa log server dan matikan debug di produksi. Isi error tidak disalin ke laporan.")
        for index, form in enumerate(page.forms, 1):
            if not form["password"]:
                continue
            action = urljoin(urljoin(url, page.base or ""), form["action"]) if form["action"] else url
            evidence = {"url": url, "form": index, "method": form["method"]}
            if form["method"] == "get":
                self.emit("MEDIUM", "Website Bug", "Form password menggunakan GET",
                          "Pengiriman HTML standar menaruh password di URL; perilaku JavaScript belum diuji.", "MEDIUM", evidence,
                          "Gunakan POST melalui HTTPS dan hindari kredensial di URL.")
            if urlparse(url).scheme == "http" or urlparse(action).scheme == "http":
                self.emit("HIGH", "Website Bug", "Form password melalui HTTP",
                          "Halaman atau tujuan form tidak menggunakan HTTPS.", "HIGH", evidence,
                          "Gunakan HTTPS untuk halaman dan action form.")
        return page

    def crawl_candidate(self, reference: str, base: str) -> str | None:
        try:
            url = urldefrag(urljoin(base, reference))[0]
            p = urlparse(url)
            if (p.scheme not in ("http", "https") or p.username is not None or p.password is not None
                    or self.origin(url) != self.origin(self.final_url) or p.query):
                return None
            # Hindari tautan aksi umum; form tidak pernah dikirim.
            if re.search(r"(?:^|[/_.-])(logout|signout|delete|remove|unsubscribe|checkout|purchase|reset|activate)(?:$|[/_.-])", p.path, re.I):
                return None
            if any(p.path.rstrip("/").lower().endswith("/" + path.rstrip("/").lower()) for path in SENSITIVE_PATHS):
                return None
            return url
        except ValueError:
            return None

    def check_website_bugs(self):
        print("\n[+] Memeriksa bug HTML, tautan, dan resource internal...")
        pending = deque([(self.final_url, self.main_response, self.main_body)])
        seen = {self.final_url}
        while pending:
            source, response, body = pending.popleft()
            if self.coverage["pages_analyzed"] >= self.max_pages:
                break
            if "html" not in response.headers.get("Content-Type", "").lower():
                continue
            page = self.analyze_page(source, body)
            base = urljoin(source, page.base or "")
            for ref in page.assets + page.links:
                target = self.crawl_candidate(ref, base)
                if target is None:
                    self.coverage["skipped_links"] += 1
                    continue
                if target in seen:
                    continue
                if self.coverage["links_checked"] >= self.max_links:
                    self.coverage["skipped_links"] += 1
                    continue
                seen.add(target)
                self.coverage["links_checked"] += 1
                try:
                    # Redirect tidak diikuti oleh crawler: target dapat berupa endpoint aksi.
                    r = self.request("GET", target, allow_redirects=False)
                except requests.RequestException as exc:
                    self.emit("INFO", "Website Bug", "Tautan tidak dapat diperiksa", type(exc).__name__, "LOW",
                              {"url": target, "source": source}, "Cek koneksi dan ulangi pemeriksaan.")
                    continue
                evidence = {"url": target, "source": source, "status": r.status_code}
                if r.status_code in (404, 410):
                    self.emit("LOW", "Website Bug", "Tautan/resource internal rusak", f"HTTP {r.status_code}.",
                              evidence=evidence, recommendation="Perbaiki URL referensi atau pulihkan resource.")
                elif r.status_code >= 500:
                    self.emit("MEDIUM", "Website Bug", "Error server pada URL internal", f"HTTP {r.status_code}.",
                              evidence=evidence, recommendation="Periksa log server dan jalur kode untuk URL ini.")
                elif r.status_code in (401, 403, 429):
                    self.emit("INFO", "Website Bug", "Pemeriksaan URL dibatasi", f"HTTP {r.status_code}; bukan bukti tautan rusak.", evidence=evidence)
                    if r.status_code == 429:
                        self.incomplete = True
                        self.emit("INFO", "Scanner", "Crawler dihentikan karena rate limit", "Kurangi frekuensi request sebelum mencoba lagi.")
                        return
                elif 300 <= r.status_code < 400:
                    self.emit("INFO", "Website Bug", "Redirect internal belum ditelusuri", "Tujuan redirect perlu diperiksa manual.", evidence=evidence)
                elif 200 <= r.status_code < 300 and "html" in r.headers.get("Content-Type", "").lower():
                    if len(pending) + self.coverage["pages_analyzed"] < self.max_pages:
                        pending.append((r.url, r, r.content.decode(r.encoding or "utf-8", "replace")))
        self.emit("INFO", "Website Bug", "Cakupan pemeriksaan bug", str(self.coverage),
                  evidence=dict(self.coverage),
                  recommendation="Uji browser terpisah untuk JavaScript, login, alur transaksi, dan logika bisnis.")

    # ---------------------------------------------------- skor & laporan
    def summarize(self) -> dict:
        counts = {s: 0 for s in SEV_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        penalty = sum(min(counts[s] * SEV_WEIGHT[s], SEV_CAP[s]) for s in SEV_ORDER)
        score = max(0, 100 - penalty)
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
        return {"score": score, "grade": grade, "counts": counts}

    def report_dir(self) -> Path:
        if self.output_dir:
            candidates = [Path(self.output_dir).expanduser()]
        else:
            home = Path.home()
            candidates = [p for p in (home / "Desktop", home / "Documents") if p.is_dir()] + [Path.cwd()]
        for p in candidates:
            try:
                out = p / "WebSecurityScannerReports"
                out.mkdir(parents=True, exist_ok=True)
                t = out / ".write_test"
                t.write_text("ok", encoding="utf-8")
                t.unlink()
                return out
            except OSError:
                continue
        raise PermissionError("Tidak menemukan folder yang dapat ditulis. Gunakan --output.")

    def generate_reports(self):
        outdir = self.report_dir()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        host = re.sub(r"[^A-Za-z0-9._-]", "_", urlparse(self.base_url).netloc) or "target"
        txt_path, json_path, html_path = (outdir / f"{host}_{stamp}.{e}" for e in ("txt", "json", "html"))

        summ = self.summarize()
        notes = [
            "Hasil scanner adalah indikasi awal, bukan bukti eksploitasi.",
            "Path sensitif diperiksa dengan HEAD agar isi file tidak diunduh.",
            "Pemeriksaan HTML/HTTP tidak menjalankan JavaScript, login, atau menguji logika bisnis; bukan pentest lengkap.",
            f"Cakupan bug: {self.coverage}; scan tidak lengkap: {self.incomplete}.",
            "Skor hanya indikator temuan, bukan jaminan keamanan; periksa cakupan dan confidence.",
            "Gunakan hanya pada sistem yang Anda miliki atau Anda memiliki izin untuk menguji.",
        ]
        now = datetime.now().isoformat(timespec="seconds")
        payload = {
            "scanner": f"PYTHON WEB SECURITY SCANNER {VERSION}", "mode": "SAFE / NON-INTRUSIVE",
            "target": self.base_url, "final_url": self.final_url, "generated_at": now,
            "request_count": self.request_count, "tls_handshakes": self.tls_handshakes,
            "coverage": self.coverage, "incomplete": self.incomplete,
            "summary": summ, "findings": [asdict(f) for f in self.findings], "notes": notes,
        }

        with txt_path.open("w", encoding="utf-8") as fh:
            fh.write("=" * 72 + f"\nPYTHON WEB SECURITY SCANNER {VERSION}\n" + "=" * 72 + "\n")
            fh.write(f"Target     : {self.base_url}\nWaktu      : {now}\nMode       : SAFE / NON-INTRUSIVE\n")
            fh.write(f"Requests   : {self.request_count}\nSkor       : {summ['score']}/100 (Grade {summ['grade']})\n")
            fh.write("Ringkasan  : " + ", ".join(f"{k}={v}" for k, v in summ["counts"].items() if v) + "\n\n")
            for f in self.findings:
                fh.write(f"[{f.severity}] {f.category} - {f.title}\n  Detail     : {f.detail}\n  Confidence : {f.confidence}\n")
                if f.evidence:
                    fh.write(f"  Evidence   : {json.dumps(f.evidence, ensure_ascii=False)}\n")
                if f.recommendation:
                    fh.write(f"  Saran      : {f.recommendation}\n")
                fh.write("\n")
            fh.write("Catatan:\n" + "".join(f"- {n}\n" for n in notes))

        json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        rows = []
        for f in sorted(self.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
            color = SEV_COLOR.get(f.severity, "#444")
            ev = escape_html(json.dumps(f.evidence, ensure_ascii=False)) if f.evidence else ""
            rows.append(
                f"<tr><td><span class='b' style='background:{color}'>{escape_html(f.severity)}</span></td>"
                f"<td>{escape_html(f.category)}</td><td><b>{escape_html(f.title)}</b><br>{escape_html(f.detail)}"
                f"{'<br><code>' + ev + '</code>' if ev else ''}</td>"
                f"<td>{escape_html(f.recommendation or '')}</td><td>{escape_html(f.confidence)}</td></tr>")
        cards = "".join(
            f"<div class='c' style='border-top:4px solid {SEV_COLOR[s]}'><b>{summ['counts'][s]}</b><span>{s}</span></div>"
            for s in SEV_ORDER)
        css = ("body{font-family:Arial,sans-serif;margin:32px;line-height:1.45;color:#111}"
               "h1{margin-bottom:4px}.meta{margin-bottom:20px}.cards{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}"
               ".c{background:#f6f6f6;padding:10px 16px;min-width:80px;display:flex;flex-direction:column;align-items:center}"
               ".c b{font-size:22px}.c span{font-size:11px;color:#555}"
               ".score{font-size:34px;font-weight:bold}table{border-collapse:collapse;width:100%}"
               "th,td{border:1px solid #ccc;padding:8px;vertical-align:top;font-size:14px}th{background:#f4f4f4;text-align:left}"
               ".b{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px}code{font-size:12px;color:#555;word-break:break-all}"
               ".note{margin-top:24px;padding:12px;background:#f7f7f7;font-size:13px}")
        html = (
            "<!doctype html><html lang='id'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Web Security Scanner Report</title><style>{css}</style></head><body>"
            f"<h1>PYTHON WEB SECURITY SCANNER {escape_html(VERSION)}</h1>"
            f"<div class='meta'><b>Target:</b> {escape_html(self.base_url)}<br><b>Waktu:</b> {escape_html(now)}<br>"
            f"<b>Mode:</b> SAFE / NON-INTRUSIVE &nbsp; <b>Requests:</b> {self.request_count}</div>"
            f"<div class='score'>{summ['score']}/100 &nbsp; Grade {summ['grade']}</div><div class='cards'>{cards}</div>"
            "<table><thead><tr><th>Severity</th><th>Kategori</th><th>Temuan</th><th>Saran</th><th>Confidence</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            "<div class='note'><b>Catatan:</b><ul>" + "".join(f"<li>{escape_html(n)}</li>" for n in notes) + "</ul></div>"
            "</body></html>")
        html_path.write_text(html, encoding="utf-8")

        print("\n[+] Report berhasil dibuat:")
        print(f"    TXT  : {txt_path}\n    JSON : {json_path}\n    HTML : {html_path}")

    # ---------------------------------------------------- run
    def _step(self, fn):
        try:
            fn()
        except BudgetExceeded as exc:
            self.incomplete = True
            self.emit("INFO", "Scanner", "Scan dihentikan sebelum semua pemeriksaan selesai", str(exc), "HIGH")
            raise
        except Exception as exc:  # satu pengecekan gagal tidak menghentikan yang lain
            self.incomplete = True
            self.emit("INFO", "Scanner", f"Pengecekan '{fn.__name__}' gagal", f"{type(exc).__name__}: {exc}"[:250], "LOW")

    def run(self) -> bool:
        print("=" * 72)
        print(f"           PYTHON WEB SECURITY SCANNER {VERSION}")
        print("             SAFE / NON-INTRUSIVE MODE")
        print("=" * 72)
        print(f"\nTarget: {self.base_url}")

        if not self.check_basic_info():
            self.incomplete = True
            self.emit("INFO", "Scanner", "Scan tidak selesai", "Halaman awal tidak dapat diperiksa.")
            self.generate_reports()
            self.session.close()
            return False
        try:
            for step in (self.check_https, self.check_tls, self.check_security_headers, self.check_cookies,
                         self.check_cors, self.check_http_methods, self.check_html_content,
                         self.check_information_disclosure, self.check_website_bugs, self.check_common_paths, self.check_wordpress,
                         self.check_email_auth):
                self._step(step)
        except BudgetExceeded:
            pass

        summ = self.summarize()
        self.generate_reports()
        print("\n" + "=" * 72)
        print(f"SCAN SELESAI  |  Skor {summ['score']}/100  Grade {summ['grade']}  |  {self.request_count} request")
        print("  " + "  ".join(f"{SEV_ICON[s]}{s}:{n}" for s, n in summ["counts"].items() if n))
        top = [f for f in self.findings if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
        if top:
            print("\nPrioritas perbaikan:")
            for f in sorted(top, key=lambda x: SEV_ORDER[x.severity]):
                print(f"  {SEV_ICON[f.severity]} [{f.severity}] {f.title}")
        print("=" * 72)
        self.session.close()
        return True


# ============================================================
# CLI
# ============================================================
def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        pass

    p = argparse.ArgumentParser(description="Safe/non-intrusive web security hardening scanner.")
    p.add_argument("url", nargs="?", help="Target URL, misalnya https://example.com")
    p.add_argument("--delay", type=float, default=REQUEST_DELAY, help=f"Jeda antar request (default {REQUEST_DELAY}s, min 0.2)")
    p.add_argument("--timeout", type=int, default=TIMEOUT, help=f"Timeout per request (default {TIMEOUT}s)")
    p.add_argument("--max-requests", type=int, default=MAX_REQUESTS, help=f"Batas total request (default {MAX_REQUESTS})")
    p.add_argument("--output", help="Folder laporan (default: Desktop/Documents/folder saat ini)")
    p.add_argument("--skip-dns", action="store_true", help="Lewati pengecekan SPF/DMARC")
    p.add_argument("--skip-tls", action="store_true", help="Lewati pengecekan TLS langsung")
    p.add_argument("--max-pages", type=int, default=10, help="Batas halaman HTML dianalisis (1–100)")
    p.add_argument("--max-links", type=int, default=30, help="Batas URL internal tambahan diperiksa (0–500)")
    p.add_argument("--insecure", action="store_true", help="Secara eksplisit izinkan sertifikat TLS tidak valid")
    p.add_argument("--yes", action="store_true", help="Lewati konfirmasi izin (Anda bertanggung jawab atas izin pengujian)")
    p.add_argument("--no-pause", action="store_true", help="Jangan menunggu ENTER di akhir")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="Exit code 2 jika ada temuan pada tingkat ini atau lebih tinggi (untuk CI)")
    args = p.parse_args(argv)

    interactive = args.url is None
    try:
        target = args.url or input("\nMasukkan URL website: ").strip()
    except EOFError:
        p.error("URL diperlukan bila stdin tidak interaktif.")
    if not target:
        print("❌ URL tidak boleh kosong.")
        return 1

    if not args.yes and not sys.stdin.isatty():
        p.error("Gunakan --yes untuk menyatakan izin pengujian pada mode noninteraktif.")
    if not args.yes and sys.stdin.isatty():
        ans = input("Apakah Anda memiliki izin untuk menguji target ini? (y/N): ").strip().lower()
        if ans not in ("y", "ya", "yes"):
            print("Dibatalkan. Uji hanya sistem yang Anda miliki atau yang Anda punya izin tertulis.")
            return 1

    try:
        scanner = Scanner(target, delay=args.delay, timeout=args.timeout, max_requests=args.max_requests,
                          output_dir=args.output, skip_dns=args.skip_dns, skip_tls=args.skip_tls,
                          max_pages=args.max_pages, max_links=args.max_links, insecure=args.insecure)
    except ValueError as exc:
        print(f"❌ {exc}")
        return 1

    ok = scanner.run()
    if interactive and not args.no_pause:
        try:
            input("\nTekan ENTER untuk menutup...")
        except EOFError:
            pass
    if not ok:
        return 1
    if args.fail_on:
        limit = SEV_ORDER[args.fail_on]
        if any(SEV_ORDER[f.severity] <= limit for f in scanner.findings):
            return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan dibatalkan pengguna.")
        sys.exit(130)
