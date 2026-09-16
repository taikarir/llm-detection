"""Measures TRUE precision of the algorithmic re-matcher (detect_technologies_regex.py)
against independent ground truth: the official Wappalyzer analyze() result for each
domain.

This script re-scans every domain with the real Wappalyzer engine (no LLM calls,
cheap and deterministic) to get ground truth, then diffs it against the already
computed regex_detected_results.json.

Scoring is restricted to technology names that exist in BOTH the LLM-authored
signature database and Wappalyzer's own tech_db
Detections outside that overlap (things the
LLM named that Wappalyzer's db has simply never heard of) can't be scored right or
wrong this way; they're written out separately for manual audit instead of being
counted as false positives.

Resumable: the Wappalyzer ground-truth scan writes wappalyzer_ground_truth.json after
every domain, so an interrupted run picks back up instead of re-scanning from zero.
"""
import csv
import json
import os
import re

from wappalyzer import Wappalyzer
from wappalyzer.core.config import tech_db

BASE_DIR = os.path.dirname(__file__)
DOMAINS_CSV = os.path.join(BASE_DIR, "sample-domains.csv")
REGEX_RESULTS_JSON = os.path.join(BASE_DIR, "regex_detected_results.json")
SIGNATURES_JSON = os.path.join(BASE_DIR, "detected_technologies.json")
GROUND_TRUTH_JSON = os.path.join(BASE_DIR, "wappalyzer_ground_truth.json")
OUT_JSON = os.path.join(BASE_DIR, "precision_report.json")

# Same alias/normalization rules test.py uses to line up LLM names with Wappalyzer names.
# Only verified true renames/spelling variants of the SAME product go here -- NOT
# same-vendor-different-product pairs (e.g. "Google Ad Manager" vs "Google Tag Manager",
# "Adobe Audience Manager" vs "Adobe Experience Platform Identity Service"). Those looked
# like alias candidates in FP/FN co-occurrence mining against the 500-domain run but are
# genuinely distinct products; merging them would inflate precision/recall by scoring
# artifact rather than fixing anything. Checked empirically against detected_technologies_500_openai.json
# before adding each entry below.
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
    if lower in ALIASES:
        return ALIASES[lower]
    stripped = re.sub(r"\s+v?\d[\d\.x\-]*$", "", lower).strip()
    if stripped in ALIASES:
        return ALIASES[stripped]
    return stripped


def is_match(a: str, b: str) -> bool:
    na, nb = normalize(a), normalize(b)
    if na == nb:
        return True
    return na in nb or nb in na


def load_domains(csv_path: str) -> list[str]:
    urls = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row["domain"].strip()
            if domain:
                urls.append(f"https://{domain}")
    return urls


def load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def scan_ground_truth(urls: list[str], resume_path: str = GROUND_TRUTH_JSON) -> dict:
    """Runs the real Wappalyzer engine against every domain. Writes after each domain
    so an interrupted/killed run doesn't lose completed work."""
    ground_truth = {}
    if os.path.exists(resume_path):
        ground_truth = load_json(resume_path)
        print(f"[resume] loaded {len(ground_truth)} previously-scanned domains from {resume_path}")

    with Wappalyzer(workers=1, timeout=30) as scanner:
        for i, url in enumerate(urls, 1):
            if url in ground_truth:
                continue
            print(f"[{i}/{len(urls)}] scanning {url}")
            try:
                result = scanner.analyze(url)
                names = list(result.get(url, {}).keys())
            except Exception as e:
                print(f"  [error] {url}: {e}")
                names = []
            ground_truth[url] = names
            with open(resume_path, "w") as f:
                json.dump(ground_truth, f, indent=2, sort_keys=True)
    return ground_truth


def score(regex_results: dict, ground_truth: dict, llm_all_names: list, wap_all_names: list) -> dict:
    """A predicted name is scorable if it fuzzy-matches (is_match) *some* entry in
    Wappalyzer's full tech_db -- i.e. Wappalyzer's schema is capable of confirming or
    denying it at all. A ground-truth name is scorable if it fuzzy-matches some name
    the LLM signature corpus produced anywhere in the sample -- i.e. the algorithmic
    matcher had a structural chance of ever finding it. Using the same is_match used
    for the actual TP/FP/FN comparison (rather than a separate exact-string
    intersection) keeps "is this name knowable" and "did it match" consistent.
    Returns per-domain and aggregate precision/recall/F1, plus a sample of unscored
    detections for manual audit."""
    per_domain = {}
    agg_tp = agg_fp = agg_fn = 0
    unscored = []

    for url, predicted in regex_results.items():
        truth = ground_truth.get(url, [])
        predicted_names = list(predicted.keys()) if isinstance(predicted, dict) else list(predicted)

        predicted_scored = [p for p in predicted_names if any(is_match(p, w) for w in wap_all_names)]
        predicted_unscored = [p for p in predicted_names if not any(is_match(p, w) for w in wap_all_names)]
        truth_scored = [t for t in truth if any(is_match(t, l) for l in llm_all_names)]

        tp = [p for p in predicted_scored if any(is_match(p, t) for t in truth_scored)]
        fp = [p for p in predicted_scored if not any(is_match(p, t) for t in truth_scored)]
        fn = [t for t in truth_scored if not any(is_match(t, p) for p in predicted_scored)]

        precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else None
        recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and (precision + recall) > 0
            else None
        )

        per_domain[url] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "unscored_predictions": predicted_unscored,
        }
        agg_tp += len(tp)
        agg_fp += len(fp)
        agg_fn += len(fn)
        unscored.extend((url, p) for p in predicted_unscored)

    agg_precision = agg_tp / (agg_tp + agg_fp) if (agg_tp + agg_fp) else None
    agg_recall = agg_tp / (agg_tp + agg_fn) if (agg_tp + agg_fn) else None
    agg_f1 = (
        2 * agg_precision * agg_recall / (agg_precision + agg_recall)
        if agg_precision is not None and agg_recall is not None and (agg_precision + agg_recall) > 0
        else None
    )

    return {
        "per_domain": per_domain,
        "aggregate": {
            "true_positives": agg_tp,
            "false_positives": agg_fp,
            "false_negatives": agg_fn,
            "precision": agg_precision,
            "recall": agg_recall,
            "f1": agg_f1,
        },
        "unscored_sample": unscored[:30],
        "unscored_total": len(unscored),
    }


def print_report(result: dict) -> None:
    agg = result["aggregate"]
    print("\n" + "=" * 60)
    print("TRUE PRECISION vs. WAPPALYZER GROUND TRUTH")
    print("=" * 60)
    print(f"  TP={agg['true_positives']}  FP={agg['false_positives']}  FN={agg['false_negatives']}")
    print(f"  Precision: {agg['precision']:.1%}" if agg["precision"] is not None else "  Precision: n/a")
    print(f"  Recall:    {agg['recall']:.1%}" if agg["recall"] is not None else "  Recall:    n/a")
    print(f"  F1:        {agg['f1']:.1%}" if agg["f1"] is not None else "  F1:        n/a")
    print(
        f"\n  {result['unscored_total']} detections had no name-match in Wappalyzer's tech_db "
        f"(unverifiable automatically -- sample below for manual audit):"
    )
    for url, name in result["unscored_sample"]:
        print(f"    {name}  ({url})")


if __name__ == "__main__":
    domains = load_domains(DOMAINS_CSV)
    regex_results = load_json(REGEX_RESULTS_JSON)
    signatures = load_json(SIGNATURES_JSON)

    llm_all_names = list(signatures.keys())
    wap_all_names = list(tech_db.keys())
    print(
        f"LLM signature db: {len(llm_all_names)} names. Wappalyzer tech_db: "
        f"{len(wap_all_names)} names."
    )

    ground_truth = scan_ground_truth(domains)

    result = score(regex_results, ground_truth, llm_all_names, wap_all_names)
    with open(OUT_JSON, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
    print(f"\nWrote {OUT_JSON}")
    print_report(result)
