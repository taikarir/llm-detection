import os
import csv
import re
import sqlite3
import json
import random
from collections import Counter
from datetime import datetime
from langgraph.func import entrypoint, task
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")
model = ChatOpenAI(model="gpt-5.6-luna", api_key=api_key)
nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

from langchain.tools import tool
from langchain.chat_models import init_chat_model
from langgraph.graph import add_messages
from langchain.messages import (
    SystemMessage,
    HumanMessage,
    ToolCall,
)
from langchain_core.messages import BaseMessage
from langgraph.func import entrypoint, task

from bs4 import BeautifulSoup
import urllib.parse
import asyncio
import requests

from playwright.async_api import async_playwright
from wappalyzer import Wappalyzer
from wappalyzer.core.config import tech_db
from wappalyzer.parsers.js import get_js


from enum import Enum
from typing import Any, List
import json
from pydantic import BaseModel, Field

class QuotaExhaustedError(Exception):
    """Raised when the LLM API returns a rate/quota error (HTTP 429)."""


class SignalType(str, Enum):
    HEADER = "header"
    COOKIE = "cookie"
    SCRIPT_SRC = "script_src"
    INLINE_SCRIPT = "inline_script"
    JS_GLOBAL = "js_global"
    META_TAG = "meta_tag"
    LINK_TAG = "link_tag"
    DOM_ATTRIBUTE = "dom_attribute"
    IFRAME_SRC = "iframe_src"
    HTML_COMMENT = "html_comment"
    IMPLIED = "implied"

class NewTechnology(BaseModel):
    name: str = Field(description="canonical technology name without version numbers")
    type: SignalType = Field(description="the category of signal that identifies this technology")
    signature: str = Field(
        description=(
            "the exact raw value from the page that confirms this technology — "
            "not a description. Examples: "
            "header → 'x-powered-by: PHP/8.1.2'; "
            "cookie → '_ga=GA1.2.123456789.1234567890'; "
            "script_src → 'https://www.googletagmanager.com/gtm.js?id=GTM-XXXX'; "
            "inline_script → 'gtag(\"config\", \"G-ABC123XYZ\")'; "
            "js_global → '__webpack_require__'; "
            "meta_tag → '<meta property=\"og:title\" content=\"...\">'; "
            "implied → 'inferred from: WordPress detected'"
        )
    )

class NewTechnologyListResponse(BaseModel):
    technologies: list[NewTechnology] = Field(description="a collection of structured technologies")


DB_NAME = "technology_cpe_cache.db"
CPE_DB_NAME = "nvd_official_cpes.db"

def init_db():
    """Initializes the local SQLite database for caching CPE mappings."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cpe_mappings (
                wappalyzer_name TEXT PRIMARY KEY,
                cpe_string_base TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
def get_cached_cpe(wappalyzer_name: str) -> str:
    """Retrieves a cached CPE base pattern from the database."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT cpe_string_base FROM cpe_mappings WHERE wappalyzer_name = ?", (wappalyzer_name,))
        result = cursor.fetchone()
        return result[0] if result else None
def save_cpe_to_cache(wappalyzer_name: str, cpe_string_base: str):
    """Caches a newly generated CPE base configuration."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cpe_mappings (wappalyzer_name, cpe_string_base, updated_at)
            VALUES (?, ?, ?)
        """, (wappalyzer_name, cpe_string_base, datetime.utcnow().isoformat()))
        conn.commit()

def choose_cpe_via_llm(wappalyzer_name: str) -> str:
    """Uses a direct, isolated call to the model to parse technology names into CPEs."""
    system_instruction = (
        "You are a cybersecurity tool that converts vendor marketing names into official NIST CPE 2.3 format strings.\n"
        "Format syntax: cpe:2.3:[part]:[vendor]:[product]:*:*:*:*:*:*:* (Use * for version placeholders)\n"
        "Rules: Use 'a' for application, 'o' for OS, 'h' for hardware. Keep fields lowercase and alphanumerical.\n"
        "Output ONLY the raw valid CPE string. Do not use markdown blocks or conversational text headers."
    )
    
    response = model.invoke([
        SystemMessage(content=system_instruction),
        HumanMessage(content=f"Convert this software target name: '{wappalyzer_name}'")
    ])
    print(response)
    return response.content[0]["text"].strip()

@tool
def scrape_url(url: str) -> str:
    """Scrape the text content of a webpage by URL.

    Uses Playwright to handle JavaScript rendering and BeautifulSoup to parse the HTML.

    Args:
        url: The complete HTTP/HTTPS URL of the webpage to scrape.
    """
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.goto(url, wait_until="networkidle")

        html_content = page.content()
        browser.close()

    soup = BeautifulSoup(html_content, "html.parser")
    for script_or_style in soup(["script", "style"]):
        script_or_style.decompose()
    clean_text = soup.get_text(separator=" ")
    lines = (line.strip() for line in clean_text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))

    return "\n".join(chunk for chunk in chunks if chunk)

@tool
def search_local_cpes(keyword: str, limit: int = 500) -> list[dict]:
    """Instantly retrieves CPE rows matching the specific technology

    Args:
        keyword: the text to be matched to the title of a technology in the database
        limit: the max amount of CPEs to be returned

    """
    # Enforce syntax boundaries to find matching sub-elements anywhere inside the string
    search_pattern = f"%{keyword}%"
    print(keyword)

    with sqlite3.connect(CPE_DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT cpe_name
            FROM cpe_entries
            WHERE cpe_name LIKE ? OR title_en LIKE ?
            LIMIT ?
        """, (search_pattern, search_pattern, limit))
        return [dict(row) for row in cursor.fetchall()]

from langchain.tools import tool
from langchain_core.messages import SystemMessage, HumanMessage
import json

@tool
def select_best_matching_cpe(cpe_list_json: str, detected_technology_name: str) -> str:
    """Analyzes a list of candidate CPE strings and selects the absolute best match 
    for the specific technology name detected on the target infrastructure.

    Args:
        cpe_list_json: A JSON string containing the list of candidate CPE strings or objects.
        detected_technology_name: The target marketing name found by the scanner (e.g. 'Amazon Cloudfront').
    """
    try:
        parsed_data = json.loads(cpe_list_json)
        
        # Handle cases where the input is a list of dictionaries or a raw list of strings
        if isinstance(parsed_data, list):
            candidates = []
            for item in parsed_data:
                if isinstance(item, dict) and "cpe_name" in item:
                    candidates.append(item["cpe_name"])
                elif isinstance(item, str):
                    candidates.append(item)
        else:
            return "Error: Invalid format. Input must be a valid JSON array list of options."
            
    except Exception as e:
        return f"Error parsing candidate list string: {str(e)}"

    if not candidates:
        return "Error: The candidate CPE list is empty."

    system_instruction = (
        "You are an expert cybersecurity platform engineer specializing in NIST CPE 2.3 syntax.\n"
        "Your task is to review a list of candidate CPE strings and select the one that best captures "
        "the core application or platform layer matching the user's detected technology name.\n\n"
        "Selection Rules:\n"
        "1. Prioritize the application layer ('cpe:2.3:a:...') for web tech over hardware ('h') or OS ('o').\n"
        "2. Prefer generic product variants containing wildcards ('*') over hyper-specific legacy editions unless requested.\n"
        "3. Output ONLY the raw, selected valid CPE string. Do not include markdown ticks, descriptions, or conversation."
    )

    prompt_content = (
        f"Detected Technology Name: '{detected_technology_name}'\n\n"
        f"Candidate CPE Strings:\n" + "\n".join(f"- {cpe}" for cpe in candidates)
    )

    try:
        response = model.invoke([
            SystemMessage(content=system_instruction),
            HumanMessage(content=prompt_content)
        ])
        print(response.content.strip())
        return response.content.strip()
        
    except Exception as e:
        return f"Error executing model comparison routing pass: {str(e)}"


@tool
def get_vulnerabilities(cpe_string: str) -> str:
    """Queries the official NIST National Vulnerability Database (NVD) API 2.0

    to discover active CVE flaws linked to a specific CPE identifier.

    Args:
        cpe_string: The precise, uniform 13-field CPE 2.3 string identifier.
    """
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # 2. Target the specific technology using the official cpeName query argument
    params = {
        "virtualMatchString": cpe_string,
        "resultsPerPage": 20  # Safeguard boundary limiting chunk response size
    }
    
    #headers = {
    #    "User-Agent": "CybersecurityScannerAgent/1.0"
    #}
    headers = {}
    
    print(f"[NVD API QUERY] Fetching vulnerability metrics for: {cpe_string}")
    
    try:
        # Standard API calls without a custom key require a 6-second delay to avoid bans
        time.sleep(6) 
        
        response = requests.get(nvd_url, params=params, headers=headers, timeout=15)
        
        if response.status_code == 403:
            return "Error: Access denied by NIST NVD. (Rate limit hit or blocked agent headers)."
        if response.status_code != 200:
            return f"Error: NIST API responded with unexpected status code {response.status_code}."
        # print(response.url)
        vulnerabilities_data = response.json()
        # print(vulnerabilities_data)
        
    except requests.exceptions.Timeout:
        return "Error: The connection request to the NIST NVD database timed out."
    except Exception as e:
        return f"Error connecting to NVD interface engine: {str(e)}"
    return vulnerabilities_data

@tool
def annotate_cves(raw_nvd_json_string: str) -> str:
    """Takes a raw JSON dump or payload string from the NVD API, processes its descriptions, 
    and outputs a structured, annotated JSON array matching the strict research schema format.

    Args:
        raw_nvd_json_string: The raw JSON text response string returned from the NVD API endpoint.
    """
    try:
        nvd_json_data = json.loads(raw_nvd_json_string)
    except Exception as e:
        return json.dumps({"error": f"Invalid JSON string format passed to tool: {str(e)}"})

    # Bind the structured output layout to your preview Gemini model reference instance
    structured_model = model.with_structured_output(Annotation)
    
    system_instruction = (
        "You are an advanced cybersecurity intelligence engineer. Your job is to extract explicit metadata "
        "from the provided NVD CVE structural dump and output it inside a strictly typed schema configuration layer.\n\n"
        "Guidelines:\n"
        "- Assess descriptions to map behavior types to correct 'Aspect' enumerations.\n"
        "- Build explicit 'spans' arrays mapping the integer indices of significant phrases (like paths or methods) back to the base context block string.\n"
        "- Return dates and timestamps as plain clean strings matching the model instructions."
    )
    if isinstance(nvd_json_data, dict):
        # Format A: If it's a standard complete NVD payload dictionary wrapper
        vulnerabilities = nvd_json_data.get("vulnerabilities", [])
    elif isinstance(nvd_json_data, list):
        # Format B: If the previous tool already extracted a direct list of objects
        vulnerabilities = nvd_json_data
    else:
        # Fallback handling block
        vulnerabilities = [] 
    extracted_records = []
    
    for idx, item in enumerate(vulnerabilities):
        cve_wrapper = item.get("cve", {})
        cve_id = cve_wrapper.get("id", f"UNKNOWN-{idx}")
        
        # Pull English descriptive summaries out to feed contextual processing steps
        descriptions = cve_wrapper.get("descriptions", [])
        english_context = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
        
        if not english_context:
            continue

        # Package raw supporting metrics variables to travel downstream in your custom parameters tracking layer
        cvss_metrics = cve_wrapper.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        
        prompt_payload = {
            "cve_id": cve_id,
            "context_text": english_context,
            "metrics": cvss_metrics,
            "published_date": cve_wrapper.get("published", "")
        }
        
        try:
            # Invoke structured parser pipelines using messages interfaces
            structured_annotation = structured_model.invoke([
                SystemMessage(content=system_instruction),
                HumanMessage(content=f"Analyze and classify this data block: {json.dumps(prompt_payload)}")
            ])
            
            # Serialize the Pydantic instance directly into a dictionary format
            extracted_records.append(structured_annotation.model_dump())
            
        except Exception as e:
            print(f"[EXTRACTION ERROR] Failed to clean validation parse steps for {cve_id}: {str(e)}")
            
    print(json.dumps(extracted_records, indent=2))
    return extracted_records

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


async def _scan_url(url: str, timeout: int = 30) -> dict:
    """Fetches a page with a plain persistent Playwright context and extracts raw fingerprint signals.

    Returns:
        html: fully rendered page HTML
        headers: HTTP response headers from the main document request
        cookies: cookie name→value dict after page load
        js_globals: global variable dict parsed from all inline scripts
        script_srcs: list of all external script src URLs
        inline_scripts: list of raw inline script body strings (≤2000 chars each)
    """
    import tempfile, shutil
    user_data_dir = tempfile.mkdtemp(prefix="pw-scan-")
    captured_headers = {}

    try:
        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(
                user_data_dir,
                headless=True,
                user_agent=USER_AGENT,
                viewport={"width": 1366, "height": 900},
                ignore_https_errors=True,
                args=["--disable-dev-shm-usage", "--no-first-run"],
            )
            context.set_default_timeout(timeout * 1000)
            page = context.pages[0] if context.pages else await context.new_page()

            async def on_response(response):
                if response.request.resource_type == "document" and not captured_headers:
                    captured_headers.update(dict(response.headers))

            page.on("response", on_response)

            try:
                await page.goto(url, wait_until="load", timeout=timeout * 1000)
            except Exception:
                try:
                    await page.evaluate("() => window.stop()")
                except Exception:
                    pass

            html = await page.content()
            raw_cookies = await context.cookies()
            await context.close()
    finally:
        shutil.rmtree(user_data_dir, ignore_errors=True)

    soup = BeautifulSoup(html, "html.parser")
    js_globals = {}
    script_srcs = []
    inline_scripts = []
    for tag in soup.find_all("script"):
        src = tag.get("src", "")
        if src:
            script_srcs.append(src)
        elif tag.string and tag.string.strip():
            body = tag.string.strip()
            globals_dict, _, _ = get_js(body)
            js_globals.update(globals_dict)
            inline_scripts.append(body[:4000])

    return {
        "html": html,
        "headers": captured_headers,
        "cookies": {c["name"]: c["value"] for c in raw_cookies},
        "js_globals": js_globals,
        "script_srcs": script_srcs,
        "inline_scripts": inline_scripts,
    }


def scan_url(url: str, timeout: int = 30) -> dict:
    """Sync wrapper around _scan_url."""
    return asyncio.run(_scan_url(url, timeout))


def _build_llm_signal_context(scan: dict) -> str:
    """Formats the raw signals from a browser scan into a structured prompt block for the LLM."""
    from bs4 import Comment
    soup = BeautifulSoup(scan["html"], "html.parser")
    lines = []

    lines.append("=== HTTP Response Headers ===")
    lines.append(json.dumps(scan["headers"], indent=2))

    lines.append("\n=== Cookies ===")
    lines.append(json.dumps(scan["cookies"], indent=2))

    lines.append("\n=== Root Element Attributes (<html> and <body>) ===")
    html_tag = soup.find("html")
    body_tag = soup.find("body")
    if html_tag:
        attrs = " ".join('%s="%s"' % (k, v) for k, v in html_tag.attrs.items())
        lines.append(f"<html {attrs}>")
    if body_tag:
        attrs = " ".join('%s="%s"' % (k, v) for k, v in body_tag.attrs.items())
        lines.append(f"<body {attrs}>")

    lines.append("\n=== Meta Tags ===")
    for tag in soup.find_all("meta"):
        lines.append(str(tag))

    lines.append("\n=== Link Tags ===")
    for tag in soup.find_all("link"):
        lines.append(str(tag))

    lines.append("\n=== Script Sources ===")
    for src in scan["script_srcs"]:
        lines.append(src)

    lines.append("\n=== Inline Script Bodies ===")
    for i, body in enumerate(scan.get("inline_scripts", [])):
        lines.append(f"--- script[{i}] ---")
        lines.append(body)

    lines.append("\n=== JS Global Variables (parsed from inline scripts) ===")
    lines.append(json.dumps(scan["js_globals"], indent=2, default=str))

    lines.append("\n=== Iframe Sources ===")
    for tag in soup.find_all("iframe"):
        src = tag.get("src", "").strip()
        if src:
            lines.append(src)

    lines.append("\n=== Elements with data-* or framework attributes ===")
    framework_attrs = re.compile(r'^(data-|ng-|v-|x-|wire:|alpine)')
    seen_attrs: set = set()
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if framework_attrs.match(attr) and attr not in seen_attrs:
                seen_attrs.add(attr)
                val_str = val if isinstance(val, str) else " ".join(val)
                lines.append(f'{tag.name}[{attr}="{val_str[:120]}"]')

    lines.append("\n=== fetchpriority / loading / decoding attributes (feature detection) ===")
    feature_attrs = {"fetchpriority", "loading", "decoding"}
    found_features: set = set()
    for tag in soup.find_all(True):
        for attr in feature_attrs:
            if tag.get(attr) and attr not in found_features:
                found_features.add(attr)
                lines.append(f'{attr} attribute present on <{tag.name}> (e.g. {tag.get(attr)})')

    lines.append("\n=== Noscript Tags ===")
    for tag in soup.find_all("noscript"):
        content = str(tag)[:500]
        if content.strip():
            lines.append(content)

    lines.append("\n=== HTML Comments ===")
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        stripped = comment.strip()
        if stripped:
            lines.append(f"<!-- {stripped[:300]} -->")

    return "\n".join(lines)


SYSTEM_PROMPT = (
    "You are a web technology fingerprinting expert. Given raw browser signals, "
    "identify every third-party or platform TECHNOLOGY in use — a named product, "
    "service, library, or framework built by a specific vendor or open-source "
    "project (e.g. Google Tag Manager, React, Cloudflare, Stripe, WordPress).\n\n"

    "DO NOT report generic web-platform features, HTTP/W3C standards, or browser "
    "APIs as technologies — these have no vendor and are not fingerprintable "
    "products. Examples of things to NEVER output: JSON-LD, Schema.org, lazy "
    "loading, Priority Hints / fetchpriority, Web Storage, IndexedDB, "
    "MutationObserver, Manifest, Brotli, X-Frame-Options, Content-Security-Policy, "
    "Strict-Transport-Security, Core Web Vitals, Single Page Application, Open "
    "Graph. If a signal is just standards-track HTML/HTTP behavior with no "
    "specific vendor attached, skip it.\n\n"

    "EVERY signature must be copy-pasted verbatim from the raw signals below — "
    "never inferred from a domain name, company association, or general "
    "knowledge. 'aws.dev looks like an AWS domain' is NOT evidence. If you "
    "cannot point to an exact header, cookie, script URL, DOM attribute, or "
    "text string that is ALREADY shown to you, do not report it.\n\n"

    "Your 'signature' field will be used verbatim as a case-insensitive "
    "substring match (or a CSS selector for dom_attribute) against a fresh "
    "scan of this same channel — not by you, by a separate program, later, "
    "with no further judgment applied. Pick the most SPECIFIC and "
    "DISCRIMINATING substring available: a full script path, not a bare "
    "shared CDN domain; a distinctive config key or SDK identifier, not a "
    "single common word or generic value like '1' or 'true'.\n\n"

    "Work through each signal category systematically:\n\n"
    "1. HTTP HEADERS — for every header, ask: does this reveal a web server, runtime, CDN, "
    "protocol version, or platform? (e.g. 'server', 'x-powered-by', 'alt-svc', vendor-specific x-* headers)\n\n"
    "2. COOKIES — for each cookie name, what analytics platform, CMS, ad network, or "
    "session manager set it?\n\n"
    "3. META TAGS — what CMS, SEO tool, or social protocol do the name/property values indicate?\n\n"
    "4. LINK TAGS — what font services, feed formats (RSS/Atom), manifests, or CSS frameworks "
    "are referenced by rel and href?\n\n"
    "5. SCRIPT SRC URLS — for each URL, identify the vendor and product from the domain and "
    "filename. Every third-party script src is a fingerprint.\n\n"
    "6. INLINE SCRIPT BODIES — what SDK initialization calls, configuration objects, or "
    "library-specific API patterns (e.g. function names, global assignments) appear?\n\n"
    "7. JS GLOBALS — what frameworks, libraries, or platform SDKs do the global variable "
    "names indicate?\n\n"
    "8. DOM ATTRIBUTES — what frameworks (not browser features) do data-*, ng-*, v-*, "
    "or other non-standard attributes indicate?\n\n"
    "9. IMPLIED TECHNOLOGIES — only when structurally certain (e.g. a specific CMS "
    "implies its known runtime language), mark as implied. Do not speculate.\n\n"

    "NAMING — use exactly one canonical entry per real-world technology, even if "
    "your evidence for it appears under multiple names or in multiple places. Use "
    "the vendor's current primary brand name: 'Amazon Web Services' not 'AWS', "
    "'Meta Pixel' not 'Facebook Pixel', 'Google Analytics' not 'GA4' or 'gtag.js'. "
    "If you already output a technology once in this response, do not output a "
    "near-duplicate under a different name for the same evidence. "
    "No version numbers in the name."
)


def _llm_detect_technologies(url: str, scan: dict, already_found: list[str] | None = None) -> list[dict]:
    """Asks the LLM to identify technologies from the same raw signals Wappalyzer uses.

    Pass already_found on the second pass to seed the LLM with first-pass results so it
    can reason about implied technologies and catch what it missed.

    Returns a list of dicts with 'name' and 'signature' keys.
    """
    signal_context = _build_llm_signal_context(scan)

    if already_found:
        found_block = (
            "\n\nAlready detected in a previous pass:\n"
            + "\n".join(f"  - {t}" for t in already_found)
            + "\n\nGiven these, look harder for anything they imply or that you may have missed. "
            "Do NOT re-list technologies already detected above — only output NEW ones."
        )
        user_prompt = f"URL: {url}\n\n{signal_context}{found_block}"
    else:
        user_prompt = f"URL: {url}\n\n{signal_context}"

    structured_model = model.with_structured_output(NewTechnologyListResponse)
    try:
        response = structured_model.invoke([
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=user_prompt),
        ])
        return [{"name": t.name, "type": t.type.value, "signature": t.signature} for t in response.technologies]
    except Exception as e:
        msg = str(e)
        msg_lower = msg.lower()
        quota_markers = (
            "resource_exhausted", "429", "rate_limit", "rate limit",
            "insufficient_quota", "quota exceeded",
        )
        if any(marker in msg_lower for marker in quota_markers):
            raise QuotaExhaustedError(msg) from e
        print(f"[LLM DETECTION ERROR] {url}: {e}")
        return []


WAPPALYZER_FIELD_BY_TYPE = {
    SignalType.HEADER: "headers",
    SignalType.COOKIE: "cookies",
    SignalType.JS_GLOBAL: "js",
    SignalType.META_TAG: "meta",
    SignalType.SCRIPT_SRC: "scriptSrc",
    SignalType.INLINE_SCRIPT: "scripts",
    SignalType.LINK_TAG: "dom",
    SignalType.DOM_ATTRIBUTE: "dom",
    SignalType.IFRAME_SRC: "dom",
    SignalType.HTML_COMMENT: "html",
}


def _parse_header_signature(signature: str) -> tuple[str, str]:
    """Splits 'X-Powered-By: PHP/8.1.2' into (header_name, pattern). The captured value is
    kept as the pattern, as presence-only would make them indistinguishable."""
    name, _, value = signature.partition(":")
    return name.strip(), re.escape(value.strip())


def _parse_cookie_signature(signature: str) -> tuple[str, str]:
    """Splits '_ga=GA1.2.123' into (cookie_name, pattern). Pattern is left blank, as
    baking one captured value in would never match again. The cookie name is already
    the distinguishing signal"""
    return signature.split("=", 1)[0].strip(), ""


def _parse_meta_signature(signature: str) -> tuple[str, str] | None:
    """Pulls the name/property attribute out of a raw '<meta ...>' tag string, keeping the
    escaped content value as the pattern when present (same rationale as headers)."""
    name_match = re.search(r'(?:name|property)=["\']([^"\']+)["\']', signature)
    if not name_match:
        return None
    content_match = re.search(r'content=["\']([^"\']*)["\']', signature)
    pattern = re.escape(content_match.group(1).strip()) if content_match and content_match.group(1).strip() else ""
    return name_match.group(1), pattern


# this list is defensive rather than load-bearing, these are excluded in the system prompt.
NON_TECHNOLOGY_DENYLIST = {
    "json-ld", "schema.org", "lazy loading", "priority hints", "fetchpriority",
    "web storage", "indexeddb", "mutationobserver", "manifest", "brotli",
    "x-frame-options", "content-security-policy", "content security policy",
    "strict-transport-security", "core web vitals", "single page application",
    "open graph",
}


def build_technologies_json(llm_results: list[dict]) -> dict:
    """Converts flat {name, type, signature} detections into a Wappalyzer-compatible
    technologies.json fragment: {tech_name: {headers: {...}, cookies: {...}, dom: [...], ...}}.

    Detection patterns are intentionally left as presence-only (empty string) or as the raw
    matched fragment — a maintainer should tighten/verify regexes before merging upstream.
    "implied" signals are skipped since the implying technology (not this one) is the side
    that should carry the "implies" field, and that direction can't be inferred reliably here.
    """
    fragment: dict[str, dict] = {}

    for r in llm_results:
        if r["name"].strip().lower() in NON_TECHNOLOGY_DENYLIST:
            continue
        name, sig_type_raw, signature = r["name"], r["type"], r["signature"]
        try:
            sig_type = SignalType(sig_type_raw)
        except ValueError:
            continue
        if sig_type == SignalType.IMPLIED:
            continue

        field = WAPPALYZER_FIELD_BY_TYPE.get(sig_type)
        if field is None:
            continue

        entry = fragment.setdefault(name, {"cats": [], "website": "", "description": ""})

        if sig_type == SignalType.HEADER:
            key, pattern = _parse_header_signature(signature)
            entry.setdefault("headers", {})[key] = pattern
        elif sig_type == SignalType.COOKIE:
            key, pattern = _parse_cookie_signature(signature)
            entry.setdefault("cookies", {})[key] = pattern
        elif sig_type == SignalType.JS_GLOBAL:
            entry.setdefault("js", {})[signature.strip()] = ""
        elif sig_type == SignalType.META_TAG:
            parsed = _parse_meta_signature(signature)
            if parsed:
                key, pattern = parsed
                entry.setdefault("meta", {})[key] = pattern
        elif field in ("scriptSrc", "scripts", "dom", "html"):
            bucket = entry.setdefault(field, [])
            value = signature.strip()[:200]
            if value and value not in bucket:
                bucket.append(value)

    return fragment


def merge_and_save_technologies_json(all_results: dict, out_path: str) -> dict:
    """Merges the per-URL Wappalyzer-style fragments into one technologies.json-shaped file
    so newly detected signatures can be reviewed and folded into the real database."""
    merged: dict[str, dict] = {}

    for r in all_results.values():
        for name, fields in r.get("technologies_json", {}).items():
            entry = merged.setdefault(name, {"cats": [], "website": "", "description": ""})
            for key, value in fields.items():
                if isinstance(value, dict):
                    entry.setdefault(key, {}).update(value)
                elif isinstance(value, list):
                    existing = entry.setdefault(key, [])
                    existing.extend(item for item in value if item not in existing)
                else:
                    entry[key] = value

    with open(out_path, "w") as f:
        json.dump(merged, f, indent=2, sort_keys=True)
    print(f"\n[+] Wrote {len(merged)} candidate technology signature(s) to {out_path}")
    return merged


def get_technologies(urls: List[str], ablation_p: float = 0.5, checkpoint_path: str | None = None):
    """For each URL: runs a single browser session to get both Wappalyzer detections and the raw
    signals (HTML, JS globals, cookies, headers). Then asks the LLM to identify technologies
    from those same signals and scores how many Wappalyzer detections it can recover.

    Args:
        urls: The complete list of HTTP/HTTPS URLs of the website to analyze.
        ablation_p: Fraction of Wappalyzer detections to hide from the LLM (default 0.50).
        checkpoint_path: If given, results are written to this JSON file after every domain
            (crash-safe), and any domain already present in it on startup is skipped so an
            interrupted run resumes instead of restarting from scratch.
    """
    init_db()
    RULE_CHANNELS = {'scriptSrc', 'html', 'meta', 'headers', 'url', 'dom', 'cookies', 'js', 'dns', 'certIssuer', 'robots', 'xhr'}

    combined_results = {}
    if checkpoint_path and os.path.exists(checkpoint_path):
        with open(checkpoint_path) as f:
            combined_results = json.load(f)
        print(f"[resume] loaded {len(combined_results)} previously-scanned domains from {checkpoint_path}")

    for url in urls:
        if url in combined_results:
            continue
        print(f"\n[SCANNING] {url}")

        try:
            # Wappalyzer scan for ground truth detections
            with Wappalyzer(workers=1, timeout=30) as scanner:
                wap_result = scanner.analyze(url)
            all_wap_names = list(wap_result.get(url, {}).keys())

            # Plain Playwright scan for raw signals (no Wappalyzer extension)
            scan = scan_url(url)

            # Show detection channels for each technology
            print(f"  Wappalyzer detected {len(all_wap_names)} technologies:")
            tech_channels = {}
            for name in all_wap_names:
                entry = tech_db.get(name, {})
                channels = [k for k in entry if k in RULE_CHANNELS]
                tech_channels[name] = channels if channels else ["(implied)"]
                print(f"    {name}: {tech_channels[name]}")

            print(f"  JS globals captured: {list(scan['js_globals'].keys())[:20]}")
            print(f"  Cookies captured:    {list(scan['cookies'].keys())}")
            print(f"  Script srcs:         {len(scan['script_srcs'])} found")

            # Ablation: hide ablation_p of detections from LLM
            all_wap_names_shuffled = all_wap_names.copy()
            random.shuffle(all_wap_names_shuffled)
            split = int(len(all_wap_names_shuffled) * ablation_p)
            hidden_techs = all_wap_names_shuffled[:split]
            visible_techs = all_wap_names_shuffled[split:]

            print(f"\n  Hidden from LLM ({len(hidden_techs)}):")
            for t in hidden_techs:
                print(f"    {t}: {tech_channels.get(t, ['?'])}")

            # Pass 1: LLM detection from raw signals
            llm_results_p1 = _llm_detect_technologies(url, scan)
            llm_names_p1 = [r["name"] for r in llm_results_p1]
            print(f"  [Pass 1] LLM found {len(llm_names_p1)}: {llm_names_p1}")

            # Pass 2: re-run with pass-1 results as context so the LLM can find implied/missed techs
            llm_results_p2 = _llm_detect_technologies(url, scan, already_found=llm_names_p1)
            llm_names_p2 = [r["name"] for r in llm_results_p2]
            print(f"  [Pass 2] LLM added  {len(llm_names_p2)}: {llm_names_p2}")

            # Merge: deduplicate by (name, type, signature), not name alone. Only true exact repeats are dropped.
            seen: set = set()
            llm_results = []
            for r in llm_results_p1 + llm_results_p2:
                key = (r["name"].lower().strip(), r["type"], r["signature"])
                if key not in seen:
                    seen.add(key)
                    llm_results.append(r)
            llm_names = [r["name"] for r in llm_results]

            # Structural synonyms only, brand renames and well-known abbreviations.
            # Keep in sync with precision_ground_truth.py's ALIASES.
            ALIASES = {
                "microsoft iis": "iis",
                "adobe typekit": "adobe fonts",
                "typekit": "adobe fonts",
                "twitter bootstrap": "bootstrap",
                "meta pixel": "facebook pixel",
                "google adwords": "google ads",
                "gtm": "google tag manager",
                "ga4": "google analytics",
                "aws": "amazon web services",
                "adobe launch": "adobe experience platform tags",
                "webfont loader": "web font loader",
            }

            def normalize(name: str) -> str:
                lower = name.lower().strip()
                # Apply explicit alias map first
                if lower in ALIASES:
                    return ALIASES[lower]
                # Strip trailing version numbers: "jquery 3.7.1" → "jquery", "bootstrap 5" → "bootstrap"
                stripped = re.sub(r'\s+v?\d[\d\.x\-]*$', '', lower).strip()
                if stripped in ALIASES:
                    return ALIASES[stripped]
                return stripped

            def is_match(hidden: str, llm: str) -> bool:
                h = normalize(hidden)
                l = normalize(llm)
                if h == l:
                    return True
                # Substring match handles "google analytics 4 (gtag.js)" ↔ "google analytics"
                return h in l or l in h

            recovered = [t for t in hidden_techs if any(is_match(t, l) for l in llm_names)]
            missed = [t for t in hidden_techs if not any(is_match(t, l) for l in llm_names)]

            print(f"\n  LLM found ({len(llm_names)}): {llm_names}")
            print(f"  Recovered ({len(recovered)}/{len(hidden_techs)}): {recovered}")
            print(f"  Missed: {missed}")
            if llm_results:
                print("  LLM detections:")
                for r in llm_results:
                    print(f"    [{r['type']}] {r['name']}: {r['signature']}")

            combined_results[url] = {
                "wappalyzer_all": all_wap_names,
                "shown_to_llm": visible_techs,
                "hidden_from_llm": hidden_techs,
                "llm_found": llm_names,
                "recovered": recovered,
                "missed": missed,
                "recovery_rate": len(recovered) / len(hidden_techs) if hidden_techs else None,
                "llm_signatures": [{"url": url, "name": r["name"], "type": r["type"], "signature": r["signature"]} for r in llm_results],
                "technologies_json": build_technologies_json(llm_results),
            }
        except QuotaExhaustedError as e:
            print(f"\n[QUOTA EXHAUSTED] stopping at {url}: {e}")
            print(
                f"  {len(combined_results)}/{len(urls)} domains completed and saved. "
                f"Not recording {url} as done -- re-running with the same checkpoint_path "
                f"will retry it once quota resets."
            )
            break
        except Exception as e:
            print(f"  [ERROR] {e}")
            combined_results[url] = {
                "error": str(e),
                "wappalyzer_all": [],
                "shown_to_llm": [],
                "hidden_from_llm": [],
                "llm_found": [],
                "recovered": [],
                "missed": [],
                "recovery_rate": None,
                "llm_signatures": [],
                "technologies_json": {},
            }

        if checkpoint_path:
            with open(checkpoint_path, "w") as f:
                json.dump(combined_results, f, indent=2, sort_keys=True)

    return combined_results


# Augment the LLM with tools
tools = [scrape_url]
tools_by_name = {tool.name: tool for tool in tools}
model_with_tools = model.bind_tools(tools)

@task
def call_llm(messages: list[BaseMessage]):
    """LLM decides whether to call a tool or not"""
    return model_with_tools.invoke(
        [
            SystemMessage(
                content="You are a helpful assistant tasked with determining the technologies used by a webpage"
            )
        ]
        + messages
    )


@task
def call_tool(tool_call: ToolCall):
    """Performs the tool call"""
    tool = tools_by_name[tool_call["name"]]
    return tool.invoke(tool_call)

@entrypoint()
def agent(messages: list[BaseMessage]):
    model_response = call_llm(messages).result()

    while True:
        if not model_response.tool_calls:
            break

        # Execute tools
        tool_result_futures = [
            call_tool(tool_call) for tool_call in model_response.tool_calls
        ]
        tool_results = [fut.result() for fut in tool_result_futures]
        messages = add_messages(messages, [model_response, *tool_results])
        model_response = call_llm(messages).result()

    messages = add_messages(messages, model_response)
    return messages

def load_domains(csv_path: str) -> list[str]:
    urls = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"].strip()
            if domain:
                urls.append(f"https://{domain}")
    return urls

def print_aggregate_stats(all_results: dict):
    rates = []
    total_hidden = 0
    total_recovered = 0
    total_missed_techs = Counter()
    all_signatures = []
    wap_tech_counter = Counter()
    llm_tech_counter = Counter()

    for url, r in all_results.items():
        if r["recovery_rate"] is not None:
            rates.append(r["recovery_rate"])
        total_hidden += len(r["hidden_from_llm"])
        total_recovered += len(r["recovered"])
        for t in r["missed"]:
            total_missed_techs[t] += 1
        for t in r["wappalyzer_all"]:
            wap_tech_counter[t] += 1
        for t in r["llm_found"]:
            llm_tech_counter[t] += 1
        for sig in r.get("llm_signatures", []):
            all_signatures.append(sig)

    print("\n" + "=" * 60)
    print("AGGREGATE STATS")
    print("=" * 60)
    print(f"Domains scanned:          {len(all_results)}")
    print(f"Domains with hidden techs:{sum(1 for r in all_results.values() if r['hidden_from_llm'])}")
    print(f"Avg recovery rate:        {sum(rates)/len(rates)*100:.1f}% ({len(rates)} domains scored)" if rates else "Avg recovery rate: N/A")
    print(f"Overall recovery:         {total_recovered}/{total_hidden} ({total_recovered/total_hidden*100:.1f}%)" if total_hidden else "Overall recovery: N/A")

    print(f"\nTop 15 most-missed technologies:")
    for tech, count in total_missed_techs.most_common(15):
        print(f"  {count:3d}x  {tech}")

    print(f"\nTop 20 technologies detected by Wappalyzer (across all domains):")
    for tech, count in wap_tech_counter.most_common(20):
        recovered_count = sum(1 for r in all_results.values() if tech in r["recovered"])
        print(f"  {count:3d}x  {tech}  (LLM recovered in {recovered_count} domains)")

    print(f"\nTop 20 technologies found by LLM (across all domains):")
    for tech, count in llm_tech_counter.most_common(20):
        print(f"  {count:3d}x  {tech}")

    print(f"\nAll LLM-detected signatures ({len(all_signatures)} total):")
    for s in all_signatures:
        print(f"  [{s.get('type', '?')}] {s['name']}: {s['signature']}  ({s['url']})")

if __name__ == "__main__":
    csv_path = os.path.join(os.path.dirname(__file__), "sample-domains.csv")
    urls = load_domains(csv_path)
    print(f"Loaded {len(urls)} domains from {csv_path}")

    all_results = get_technologies(urls)
    print_aggregate_stats(all_results)
    merge_and_save_technologies_json(
        all_results, os.path.join(os.path.dirname(__file__), "detected_technologies.json")
    )



