"""Algorithmic technology detector.

Loads the Wappalyzer-style signatures the LLM generated in `test.py`
(detected_technologies.json) and matches them against freshly scanned pages using
plain substring / CSS-selector checks — no LLM calls at all. The LLM is used once,
offline, to *write* signatures; this script is what runs them.
"""
import asyncio
import csv
import json
import os
import shutil
import tempfile
from typing import List

from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from wappalyzer.parsers.js import get_js

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


async def _scan_url(url: str, timeout: int = 30) -> dict:
    """Fetches a page with a plain persistent Playwright context and extracts raw fingerprint signals."""
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


def load_domains(csv_path: str) -> list[str]:
    urls = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"].strip()
            if domain:
                urls.append(f"https://{domain}")
    return urls


def load_signatures(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _matches(pattern: str, haystack: str) -> bool:
    """Plain case-insensitive substring check. Every pattern in our generated signature
    file is literal captured text (verbatim or re.escape'd), never intentional regex —
    running it through re.search() is a footgun: a JS snippet like 'window.Slick||{}'
    is *valid* regex containing an empty alternation branch ('||') that silently matches
    everything, with no re.error to trip a fallback."""
    if not pattern:
        return bool(haystack)
    return pattern.lower() in haystack.lower()


def _match_keyed(entries: dict, haystack_dict: dict) -> list[str]:
    """Matches a {key: pattern} signature block (headers/cookies) against a scanned
    {key: value} dict, case-insensitively on the key."""
    evidence = []
    lower_haystack = {k.lower(): v for k, v in haystack_dict.items()}
    for key, pattern in entries.items():
        value = lower_haystack.get(key.lower().strip())
        if value is not None and _matches(pattern, value):
            evidence.append(f"{key}={value!r}" if pattern else f"{key} present")
    return evidence


def _match_js(entries: dict, js_globals: dict, js_haystack: str) -> list[str]:
    """Exact global-name lookup first (fast, precise); falls back to a substring/regex
    search over inline script text + global values, since many LLM-written 'js' keys
    are dotted paths or code fragments rather than bare top-level identifiers."""
    evidence = []
    for key, pattern in entries.items():
        if key in js_globals and _matches(pattern, str(js_globals[key])):
            evidence.append(f"js global {key!r} present")
        elif _matches(pattern or key, js_haystack):
            evidence.append(f"js signal {key!r} found in page scripts")
    return evidence


def _match_list(patterns: list, haystacks: list[str]) -> list[str]:
    evidence = []
    for pattern in patterns:
        for haystack in haystacks:
            if _matches(pattern, haystack):
                evidence.append(pattern)
                break
    return evidence


def _match_dom(patterns: list, soup: BeautifulSoup, html: str) -> list[str]:
    """Tries each pattern as a real CSS selector first; if that's not valid CSS
    (the LLM often emitted raw attribute fragments or URLs instead), falls back to
    a plain substring search against the raw HTML."""
    evidence = []
    for pattern in patterns:
        try:
            if soup.select(pattern):
                evidence.append(pattern)
                continue
        except Exception:
            pass
        if pattern.lower() in html.lower():
            evidence.append(pattern)
    return evidence


def detect_from_scan(scan: dict, signatures: dict) -> dict:
    """Runs every signature's rules against one page scan. Returns
    {tech_name: {"confidence": n_categories_matched, "evidence": [...]}}."""
    soup = BeautifulSoup(scan["html"], "html.parser")
    js_haystack = "\n".join(scan["inline_scripts"]) + "\n" + json.dumps(scan["js_globals"], default=str)

    detected = {}
    for name, entry in signatures.items():
        evidence = []

        if entry.get("headers"):
            evidence += _match_keyed(entry["headers"], scan["headers"])
        if entry.get("cookies"):
            evidence += _match_keyed(entry["cookies"], scan["cookies"])
        if entry.get("js"):
            evidence += _match_js(entry["js"], scan["js_globals"], js_haystack)
        if entry.get("meta"):
            meta_dict = {
                (tag.get("name") or tag.get("property") or ""): (tag.get("content") or "")
                for tag in soup.find_all("meta")
            }
            evidence += _match_keyed(entry["meta"], meta_dict)
        if entry.get("scriptSrc"):
            evidence += _match_list(entry["scriptSrc"], scan["script_srcs"])
        if entry.get("scripts"):
            evidence += _match_list(entry["scripts"], scan["inline_scripts"])
        if entry.get("html"):
            evidence += _match_list(entry["html"], [scan["html"]])
        if entry.get("dom"):
            evidence += _match_dom(entry["dom"], soup, scan["html"])

        if evidence:
            detected[name] = {"confidence": len(evidence), "evidence": evidence}

    return detected


def detect_technologies(urls: List[str], signatures_path: str, checkpoint_path: str | None = None) -> dict:
    signatures = load_signatures(signatures_path)
    results = {}
    if checkpoint_path and os.path.exists(checkpoint_path):
        with open(checkpoint_path) as f:
            results = json.load(f)
        print(f"[resume] loaded {len(results)} previously-scanned domains from {checkpoint_path}")

    for url in urls:
        if url in results:
            continue
        print(f"\n[SCANNING] {url}")
        try:
            scan = scan_url(url)
        except Exception as e:
            print(f"  [ERROR] {e}")
            results[url] = {"error": str(e)}
            if checkpoint_path:
                with open(checkpoint_path, "w") as f:
                    json.dump(results, f, indent=2, sort_keys=True)
            continue

        detected = detect_from_scan(scan, signatures)
        results[url] = detected
        print(f"  Detected {len(detected)} technologies:")
        for name, info in sorted(detected.items(), key=lambda kv: -kv[1]["confidence"]):
            print(f"    {name} (confidence={info['confidence']}): {info['evidence'][:2]}")

        if checkpoint_path:
            with open(checkpoint_path, "w") as f:
                json.dump(results, f, indent=2, sort_keys=True)

    return results


if __name__ == "__main__":
    base_dir = os.path.dirname(__file__)
    csv_path = os.path.join(base_dir, "sample-domains.csv")
    signatures_path = os.path.join(base_dir, "detected_technologies.json")

    urls = load_domains(csv_path)
    print(f"Loaded {len(urls)} domains from {csv_path}")

    signatures = load_signatures(signatures_path)
    print(f"Loaded {len(signatures)} candidate signatures from {signatures_path}")

    results = detect_technologies(urls, signatures_path)

    out_path = os.path.join(base_dir, "regex_detected_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)

    total_detections = sum(len(v) for v in results.values() if isinstance(v, dict) and "error" not in v)
    print(f"\n[+] {total_detections} total technology detections across {len(urls)} domains.")
    print(f"[+] Wrote results to {out_path}")
