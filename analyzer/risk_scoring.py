"""
Deterministic Risk Scoring and Explainable Alert Generation (v1).

This module consumes multi-signal detection results from analyzer/detection_engine.py
and transforms them into:
- Deterministic numeric risk scores (0 to 100)
- Project-level severity bands (NONE, LOW, MEDIUM, HIGH, CRITICAL)
- Auditable per-rule score breakdowns
- Structured, explainable alert objects for SOC analyst review

Important limitations and design notes:
1. Rule weights represent an initial explainable scoring model, not universal constants.
2. Severity thresholds are project-level classifications.
3. The risk score is NOT a statistical probability of DNS tunneling.
4. A high risk score indicates correlated anomalous behavior requiring investigation,
   not definitive proof of DNS tunneling.
5. Future calibration requires suspicious/tunneling datasets and analyst feedback.
6. Evaluation on known-normal traffic alone cannot measure true-positive performance.
"""

from collections import Counter
import json
from math import isfinite

try:
    from analyzer.detection_engine import (
        RULE_HIGH_ENTROPY,
        RULE_HIGH_NXDOMAIN_RATIO,
        RULE_HIGH_QUERY_RATE,
        RULE_HIGH_UNIQUE_SUBDOMAINS,
        RULE_LONG_QUERIES,
        RULE_UNUSUAL_QUERY_TYPE,
        calculate_baseline,
        detect_windows,
    )
    from analyzer.dns_aggregator import WINDOW_SIZE, aggregate_dns_records
    from analyzer.dns_reader import LOG_FILE, read_dns_log
except ImportError:
    from detection_engine import (
        RULE_HIGH_ENTROPY,
        RULE_HIGH_NXDOMAIN_RATIO,
        RULE_HIGH_QUERY_RATE,
        RULE_HIGH_UNIQUE_SUBDOMAINS,
        RULE_LONG_QUERIES,
        RULE_UNUSUAL_QUERY_TYPE,
        calculate_baseline,
        detect_windows,
    )
    from dns_aggregator import WINDOW_SIZE, aggregate_dns_records
    from dns_reader import LOG_FILE, read_dns_log

# Score bounds
MIN_RISK_SCORE = 0
MAX_RISK_SCORE = 100

# Initial explainable rule weights (sum = 100)
RULE_WEIGHTS: dict[str, int] = {
    RULE_HIGH_QUERY_RATE: 15,
    RULE_HIGH_ENTROPY: 25,
    RULE_LONG_QUERIES: 20,
    RULE_HIGH_UNIQUE_SUBDOMAINS: 25,
    RULE_HIGH_NXDOMAIN_RATIO: 10,
    RULE_UNUSUAL_QUERY_TYPE: 5,
}

# Severity level names
SEVERITY_NONE = "NONE"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Configurable project-level severity minimum score thresholds:
#   0       -> NONE
#   1-24    -> LOW
#   25-49   -> MEDIUM
#   50-74   -> HIGH
#   75-100  -> CRITICAL
LOW_SEVERITY_MIN = 1
MEDIUM_SEVERITY_MIN = 25
HIGH_SEVERITY_MIN = 50
CRITICAL_SEVERITY_MIN = 75

ALERT_TITLE_SUSPICIOUS = "Potential DNS Tunneling Activity"
ALERT_TITLE_NORMAL = "Normal DNS Activity"


def _is_valid_number(value: object) -> bool:
    """Return True if value is a finite int or float (excluding booleans)."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and isfinite(value)
    )


def _extract_unique_recognized_rules(
    detection_result: object,
    weights: dict[str, int] = RULE_WEIGHTS,
) -> list[str]:
    """
    Extract deduplicated recognized rule names from a detection result while preserving order.

    Prevents double-counting duplicate rule entries and ignores unknown or malformed rules.
    """
    if not isinstance(detection_result, dict):
        return []

    if not isinstance(weights, dict):
        return []

    raw_rules = detection_result.get("triggered_rules")
    if not isinstance(raw_rules, list):
        return []

    seen: set[str] = set()
    recognized_rules: list[str] = []
    for rule in raw_rules:
        if not isinstance(rule, str):
            continue
        weight = weights.get(rule)
        if not _is_valid_number(weight) or weight <= 0:
            continue
        if rule not in seen:
            seen.add(rule)
            recognized_rules.append(rule)

    return recognized_rules


def calculate_score_breakdown(
    detection_result: object,
    weights: dict[str, int] = RULE_WEIGHTS,
) -> dict[str, int]:
    """
    Build an auditable per-rule score breakdown for a detection result.

    Respects the detection engine's `suspicious` flag: if `suspicious` is not True,
    returns an empty breakdown so single weak signals are not scored as alerts.
    """
    if not isinstance(detection_result, dict):
        return {}

    if detection_result.get("suspicious") is not True:
        return {}

    recognized_rules = _extract_unique_recognized_rules(detection_result, weights=weights)
    return {rule: int(weights[rule]) for rule in recognized_rules}


def calculate_risk_score(
    detection_result: object,
    weights: dict[str, int] = RULE_WEIGHTS,
) -> int:
    """
    Calculate a deterministic risk score in [0, 100] from a detection engine result.

    Returns 0 whenever `suspicious` is False, the input is malformed, or no recognized
    behavioral rules were triggered.
    """
    breakdown = calculate_score_breakdown(detection_result, weights=weights)
    if not breakdown:
        return MIN_RISK_SCORE

    raw_score = sum(breakdown.values())
    if raw_score <= MIN_RISK_SCORE:
        return MIN_RISK_SCORE
    if raw_score >= MAX_RISK_SCORE:
        return MAX_RISK_SCORE

    return int(raw_score)


def get_severity(score: object) -> str:
    """
    Map a numeric risk score to a project-level severity band.

    Bands:
      0       -> NONE
      1-24    -> LOW
      25-49   -> MEDIUM
      50-74   -> HIGH
      75-100  -> CRITICAL
    """
    if not _is_valid_number(score):
        return SEVERITY_NONE

    clamped = min(MAX_RISK_SCORE, max(MIN_RISK_SCORE, float(score)))
    if clamped < LOW_SEVERITY_MIN:
        return SEVERITY_NONE
    if clamped < MEDIUM_SEVERITY_MIN:
        return SEVERITY_LOW
    if clamped < HIGH_SEVERITY_MIN:
        return SEVERITY_MEDIUM
    if clamped < CRITICAL_SEVERITY_MIN:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


def _sanitize_evidence(raw_evidence: object) -> list[dict]:
    """Preserve valid structured evidence items from the detection result."""
    if not isinstance(raw_evidence, list):
        return []

    clean_evidence: list[dict] = []
    for item in raw_evidence:
        if isinstance(item, dict):
            clean_evidence.append(dict(item))
    return clean_evidence


def generate_alert(
    detection_result: object,
    weights: dict[str, int] = RULE_WEIGHTS,
) -> dict:
    """
    Generate a structured, explainable alert dictionary from a single detection result.

    Preserves the underlying evidence from detection_engine.py and includes the
    deterministic risk score, severity classification, per-rule score breakdown,
    alert title, and analyst summary.
    """
    if not isinstance(detection_result, dict):
        return {
            "title": ALERT_TITLE_NORMAL,
            "source_ip": None,
            "window_start": None,
            "window_end": None,
            "suspicious": False,
            "risk_score": MIN_RISK_SCORE,
            "severity": SEVERITY_NONE,
            "triggered_rules": [],
            "score_breakdown": {},
            "evidence": [],
            "summary": "Malformed detection input; no suspicious DNS activity identified.",
        }

    source_ip = (
        detection_result.get("source_ip")
        if isinstance(detection_result.get("source_ip"), str)
        and detection_result.get("source_ip").strip()
        else None
    )
    window_start = (
        detection_result.get("window_start")
        if _is_valid_number(detection_result.get("window_start"))
        else None
    )
    window_end = (
        detection_result.get("window_end")
        if _is_valid_number(detection_result.get("window_end"))
        else None
    )

    raw_triggered = detection_result.get("triggered_rules")
    preserved_rules = (
        [r for r in raw_triggered if isinstance(r, str)]
        if isinstance(raw_triggered, list)
        else []
    )
    evidence = _sanitize_evidence(detection_result.get("evidence"))

    breakdown = calculate_score_breakdown(detection_result, weights=weights)
    risk_score = calculate_risk_score(detection_result, weights=weights)
    is_suspicious = (detection_result.get("suspicious") is True) and (risk_score > 0)
    severity = get_severity(risk_score) if is_suspicious else SEVERITY_NONE

    if is_suspicious:
        title = ALERT_TITLE_SUSPICIOUS
        rule_list_str = ", ".join(breakdown.keys())
        summary = (
            f"Multiple correlated DNS behavioral indicators ({rule_list_str}) "
            f"suggest potentially suspicious DNS activity requiring investigation."
        )
    else:
        title = ALERT_TITLE_NORMAL
        if preserved_rules:
            summary = (
                "Isolated DNS behavioral indicator observed without sufficient "
                "multi-signal correlation; activity classified as normal."
            )
        else:
            summary = "No correlated anomalous DNS behavioral indicators detected."

    return {
        "title": title,
        "source_ip": source_ip,
        "window_start": window_start,
        "window_end": window_end,
        "suspicious": is_suspicious,
        "risk_score": risk_score,
        "severity": severity,
        "triggered_rules": preserved_rules,
        "score_breakdown": breakdown,
        "evidence": evidence,
        "summary": summary,
    }


def score_detections(
    detection_results: list[dict],
    weights: dict[str, int] = RULE_WEIGHTS,
) -> list[dict]:
    """
    Score a list of detection results in O(n) time, skipping non-dict entries safely.
    """
    if not isinstance(detection_results, list) or not detection_results:
        return []

    scored: list[dict] = []
    for result in detection_results:
        if not isinstance(result, dict):
            continue
        scored.append(generate_alert(result, weights=weights))

    return scored


def main() -> None:
    """Run the full pipeline through Risk Scoring + Explainable Alert v1 on logs/normal/dns.log."""
    dns_records = read_dns_log(LOG_FILE)
    windows = aggregate_dns_records(dns_records, window_size=WINDOW_SIZE)
    baseline = calculate_baseline(windows)
    detections = detect_windows(windows, baseline)
    scored_windows = score_detections(detections)

    total_windows = len(scored_windows)
    suspicious_windows = sum(1 for item in scored_windows if item["suspicious"])
    alerts_generated = [item for item in scored_windows if item["risk_score"] > 0]
    highest_score = (
        max(item["risk_score"] for item in scored_windows) if scored_windows else 0
    )

    score_distribution: Counter[int] = Counter(
        item["risk_score"] for item in scored_windows
    )
    severity_distribution: Counter[str] = Counter(
        item["severity"] for item in scored_windows
    )
    rule_contributions: Counter[str] = Counter()
    for item in scored_windows:
        for rule, pts in item["score_breakdown"].items():
            rule_contributions[rule] += pts

    print("--- Risk Scoring & Explainable Alert v1: Normal Dataset Report ---")
    print(f"Total Windows Scored: {total_windows}")
    print(f"Suspicious Windows: {suspicious_windows}")
    print(f"Suspicious Alerts Generated (risk_score > 0): {len(alerts_generated)}")
    print(f"Highest Observed Risk Score: {highest_score}")

    print("\n--- Score Distribution ---")
    for score, count in sorted(score_distribution.items()):
        print(f"  Score {score}: {count} window(s)")

    print("\n--- Severity Distribution ---")
    for sev in (
        SEVERITY_NONE,
        SEVERITY_LOW,
        SEVERITY_MEDIUM,
        SEVERITY_HIGH,
        SEVERITY_CRITICAL,
    ):
        print(f"  {sev}: {severity_distribution.get(sev, 0)}")

    print("\n--- Rule Contribution Totals (Suspicious Windows) ---")
    for rule, weight in RULE_WEIGHTS.items():
        print(
            f"  {rule} (weight={weight}): "
            f"{rule_contributions.get(rule, 0)} total points contributed"
        )

    if alerts_generated:
        print("\n--- Sample Suspicious Alerts ---")
        for alert in alerts_generated[:3]:
            print(json.dumps(alert, indent=4))


if __name__ == "__main__":
    main()
