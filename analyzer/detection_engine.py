"""
Explainable DNS Tunneling Detection Engine (v1).

This module evaluates 10-second per-source-IP behavioral windows produced by
analyzer/dns_aggregator.py against statistical thresholds derived from a baseline
of normal DNS traffic.

Architectural principles:
1. No single DNS feature automatically classifies traffic as DNS tunneling.
2. Each rule represents a weak behavioral indicator backed by structured evidence.
3. Multi-signal correlation requires multiple independent indicators (default >= 2)
   before marking a window as suspicious.
4. Detection is strictly separated from numeric risk scoring (which belongs to the
   subsequent pipeline stage).
"""

from collections import Counter
import json
from math import isfinite, sqrt

try:
    from analyzer.dns_aggregator import WINDOW_SIZE, aggregate_dns_records
    from analyzer.dns_reader import LOG_FILE, read_dns_log
except ImportError:
    from dns_aggregator import WINDOW_SIZE, aggregate_dns_records
    from dns_reader import LOG_FILE, read_dns_log

# Minimum number of valid windows required to compute a meaningful statistical baseline
MIN_BASELINE_WINDOWS = 2

# Minimum number of windows containing TXT queries required to establish a TXT baseline
MIN_TXT_BASELINE_WINDOWS = 2

# Minimum number of correlated weak signals required to classify a window as suspicious
MIN_CORRELATED_SIGNALS = 2

# Statistical multiplier (standard deviations above the baseline mean)
PRIMARY_STD_MULTIPLIER = 3.0
SECONDARY_STD_MULTIPLIER = 2.0

# Rule identifiers
RULE_HIGH_QUERY_RATE = "HIGH_QUERY_RATE"
RULE_HIGH_ENTROPY = "HIGH_ENTROPY"
RULE_LONG_QUERIES = "LONG_QUERIES"
RULE_HIGH_UNIQUE_SUBDOMAINS = "HIGH_UNIQUE_SUBDOMAINS"
RULE_HIGH_NXDOMAIN_RATIO = "HIGH_NXDOMAIN_RATIO"
RULE_UNUSUAL_QUERY_TYPE = "UNUSUAL_QUERY_TYPE"

ALL_RULES = (
    RULE_HIGH_QUERY_RATE,
    RULE_HIGH_ENTROPY,
    RULE_LONG_QUERIES,
    RULE_HIGH_UNIQUE_SUBDOMAINS,
    RULE_HIGH_NXDOMAIN_RATIO,
    RULE_UNUSUAL_QUERY_TYPE,
)

REQUIRED_NUMERIC_FIELDS = (
    "window_start",
    "window_end",
    "total_queries",
    "unique_queries",
    "unique_query_ratio",
    "repeated_query_ratio",
    "average_query_length",
    "maximum_query_length",
    "average_entropy",
    "maximum_entropy",
    "unique_subdomain_count",
    "nxdomain_count",
    "nxdomain_ratio",
)


def _is_valid_number(value: object) -> bool:
    """Return True if value is a finite int or float (excluding booleans)."""
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and isfinite(value)
    )


def is_valid_window(window: object) -> bool:
    """Validate that an aggregated window dictionary contains well-formed behavioral fields."""
    if not isinstance(window, dict):
        return False

    source_ip = window.get("source_ip")
    if not isinstance(source_ip, str) or not source_ip.strip():
        return False

    for field in REQUIRED_NUMERIC_FIELDS:
        val = window.get(field)
        if not _is_valid_number(val):
            return False

    if window["total_queries"] <= 0:
        return False

    if window["window_end"] < window["window_start"]:
        return False

    # Validate non-negative counts/ratios/lengths/entropies
    for non_neg_field in (
        "unique_queries",
        "unique_query_ratio",
        "repeated_query_ratio",
        "average_query_length",
        "maximum_query_length",
        "average_entropy",
        "maximum_entropy",
        "unique_subdomain_count",
        "nxdomain_count",
        "nxdomain_ratio",
    ):
        if window[non_neg_field] < 0:
            return False

    query_types = window.get("query_types")
    if query_types is not None:
        if not isinstance(query_types, dict):
            return False
        for k, v in query_types.items():
            if not isinstance(k, str) or not _is_valid_number(v) or v < 0:
                return False

    return True


def _mean_and_std(values: list[float]) -> tuple[float, float]:
    """Compute arithmetic mean and population standard deviation in O(n) time."""
    n = len(values)
    if n == 0:
        return 0.0, 0.0

    mean_val = sum(values) / n
    variance = sum((v - mean_val) ** 2 for v in values) / n
    return mean_val, sqrt(variance)


def _extract_txt_ratio(window: dict) -> float:
    """Calculate the proportion of TXT queries in a validated window."""
    total_queries = window.get("total_queries", 0)
    if not _is_valid_number(total_queries) or total_queries <= 0:
        return 0.0

    query_types = window.get("query_types")
    if not isinstance(query_types, dict):
        return 0.0

    txt_count = query_types.get("TXT", 0)
    if not _is_valid_number(txt_count) or txt_count <= 0:
        return 0.0

    return float(txt_count) / float(total_queries)


def calculate_baseline(
    windows: list[dict],
    min_windows: int = MIN_BASELINE_WINDOWS,
) -> dict:
    """
    Derive statistical behavioral thresholds from aggregated normal DNS windows.

    Methodology:
    - Primary anomaly thresholds use `mean + 3 * std` (3-sigma upper control limit)
      across valid normal windows.
    - Compound rules (entropy, query length, unique subdomains) also pair a primary
      3-sigma metric with a secondary 2-sigma metric (`mean + 2 * std`) so that:
        * Single outlier queries do not trigger window-level entropy or length rules.
        * Normal dual-stack (A + AAAA) browser bursts with many hosts but moderate
          unique_query_ratio (~0.25-0.50) do not falsely trigger unique-subdomain alerts.
    - TXT query anomaly threshold is only enabled if the baseline dataset contains at
      least `MIN_TXT_BASELINE_WINDOWS` windows with TXT queries; otherwise it is marked
      unavailable rather than defaulting to a misleading 0.0 threshold.
    """
    if not isinstance(windows, list) or not windows:
        return {
            "is_valid": False,
            "window_count": 0,
            "reason": "Empty or invalid window list provided for baseline calculation.",
            "thresholds": {},
            "stats": {},
            "txt_baseline_available": False,
        }

    valid_windows = [w for w in windows if is_valid_window(w)]
    count = len(valid_windows)

    if count < max(1, min_windows):
        return {
            "is_valid": False,
            "window_count": count,
            "reason": (
                f"Insufficient baseline data: {count} valid window(s) found, "
                f"minimum {min_windows} required."
            ),
            "thresholds": {},
            "stats": {},
            "txt_baseline_available": False,
        }

    total_queries_vals = [float(w["total_queries"]) for w in valid_windows]
    avg_entropy_vals = [float(w["average_entropy"]) for w in valid_windows]
    max_entropy_vals = [float(w["maximum_entropy"]) for w in valid_windows]
    avg_length_vals = [float(w["average_query_length"]) for w in valid_windows]
    max_length_vals = [float(w["maximum_query_length"]) for w in valid_windows]
    subdomain_vals = [float(w["unique_subdomain_count"]) for w in valid_windows]
    unique_ratio_vals = [float(w["unique_query_ratio"]) for w in valid_windows]
    nxdomain_ratio_vals = [float(w["nxdomain_ratio"]) for w in valid_windows]
    txt_ratio_vals = [_extract_txt_ratio(w) for w in valid_windows]

    tq_mean, tq_std = _mean_and_std(total_queries_vals)
    ae_mean, ae_std = _mean_and_std(avg_entropy_vals)
    me_mean, me_std = _mean_and_std(max_entropy_vals)
    al_mean, al_std = _mean_and_std(avg_length_vals)
    ml_mean, ml_std = _mean_and_std(max_length_vals)
    us_mean, us_std = _mean_and_std(subdomain_vals)
    ur_mean, ur_std = _mean_and_std(unique_ratio_vals)
    nx_mean, nx_std = _mean_and_std(nxdomain_ratio_vals)
    txt_mean, txt_std = _mean_and_std(txt_ratio_vals)

    windows_with_txt = sum(1 for r in txt_ratio_vals if r > 0.0)
    txt_baseline_available = (
        windows_with_txt >= MIN_TXT_BASELINE_WINDOWS and txt_mean > 0.0
    )
    txt_ratio_threshold = (
        txt_mean + PRIMARY_STD_MULTIPLIER * txt_std
        if txt_baseline_available
        else None
    )

    thresholds = {
        "total_queries": tq_mean + PRIMARY_STD_MULTIPLIER * tq_std,
        "average_entropy": ae_mean + PRIMARY_STD_MULTIPLIER * ae_std,
        "maximum_entropy": me_mean + SECONDARY_STD_MULTIPLIER * me_std,
        "average_query_length": al_mean + PRIMARY_STD_MULTIPLIER * al_std,
        "maximum_query_length": ml_mean + SECONDARY_STD_MULTIPLIER * ml_std,
        "unique_subdomain_count": us_mean + PRIMARY_STD_MULTIPLIER * us_std,
        "unique_query_ratio": ur_mean + SECONDARY_STD_MULTIPLIER * ur_std,
        "nxdomain_ratio": nx_mean + PRIMARY_STD_MULTIPLIER * nx_std,
        "txt_ratio": txt_ratio_threshold,
    }

    stats = {
        "total_queries": {"mean": tq_mean, "std": tq_std},
        "average_entropy": {"mean": ae_mean, "std": ae_std},
        "maximum_entropy": {"mean": me_mean, "std": me_std},
        "average_query_length": {"mean": al_mean, "std": al_std},
        "maximum_query_length": {"mean": ml_mean, "std": ml_std},
        "unique_subdomain_count": {"mean": us_mean, "std": us_std},
        "unique_query_ratio": {"mean": ur_mean, "std": ur_std},
        "nxdomain_ratio": {"mean": nx_mean, "std": nx_std},
        "txt_ratio": {
            "mean": txt_mean,
            "std": txt_std,
            "windows_with_txt": windows_with_txt,
        },
    }

    return {
        "is_valid": True,
        "window_count": count,
        "thresholds": thresholds,
        "stats": stats,
        "txt_baseline_available": txt_baseline_available,
    }


def _is_usable_baseline(baseline: object) -> bool:
    """Check whether a baseline dictionary contains usable statistical thresholds."""
    if not isinstance(baseline, dict) or not baseline:
        return False

    if baseline.get("is_valid") is False:
        return False

    thresholds = baseline.get("thresholds")
    if not isinstance(thresholds, dict) or not thresholds:
        return False

    required_thresholds = (
        "total_queries",
        "average_entropy",
        "maximum_entropy",
        "average_query_length",
        "maximum_query_length",
        "unique_subdomain_count",
        "unique_query_ratio",
        "nxdomain_ratio",
    )
    for key in required_thresholds:
        if not _is_valid_number(thresholds.get(key)):
            return False

    return True


def evaluate_rules(window: dict, baseline: dict) -> list[dict]:
    """
    Evaluate all weak behavioral detection rules for a validated window against a usable baseline.

    Returns a list of structured evidence dictionaries for each triggered rule.
    """
    thresholds = baseline["thresholds"]
    evidence: list[dict] = []

    # A. HIGH_QUERY_RATE
    total_queries = window["total_queries"]
    tq_threshold = thresholds["total_queries"]
    if total_queries > tq_threshold:
        evidence.append(
            {
                "rule": RULE_HIGH_QUERY_RATE,
                "observed": total_queries,
                "threshold": round(tq_threshold, 4),
                "reason": (
                    f"Query rate ({total_queries} queries / 10s window) is above "
                    f"the normal baseline threshold ({tq_threshold:.4f})."
                ),
            }
        )

    # B. HIGH_ENTROPY (window-level average entropy + maximum entropy check)
    avg_entropy = window["average_entropy"]
    max_entropy = window["maximum_entropy"]
    ae_threshold = thresholds["average_entropy"]
    me_threshold = thresholds["maximum_entropy"]
    if avg_entropy > ae_threshold and max_entropy > me_threshold:
        evidence.append(
            {
                "rule": RULE_HIGH_ENTROPY,
                "observed": round(avg_entropy, 4),
                "threshold": round(ae_threshold, 4),
                "reason": (
                    f"Window average entropy ({avg_entropy:.4f}) and maximum entropy "
                    f"({max_entropy:.4f}) exceed normal baseline thresholds "
                    f"(avg: {ae_threshold:.4f}, max: {me_threshold:.4f})."
                ),
            }
        )

    # C. LONG_QUERIES (window-level average query length + maximum query length check)
    avg_length = window["average_query_length"]
    max_length = window["maximum_query_length"]
    al_threshold = thresholds["average_query_length"]
    ml_threshold = thresholds["maximum_query_length"]
    if avg_length > al_threshold and max_length > ml_threshold:
        evidence.append(
            {
                "rule": RULE_LONG_QUERIES,
                "observed": round(avg_length, 4),
                "threshold": round(al_threshold, 4),
                "reason": (
                    f"Window average query length ({avg_length:.4f}) and maximum query "
                    f"length ({max_length}) exceed normal baseline thresholds "
                    f"(avg: {al_threshold:.4f}, max: {ml_threshold:.4f})."
                ),
            }
        )

    # D. HIGH_UNIQUE_SUBDOMAINS (elevated unique subdomain count paired with high unique query ratio)
    subdomain_count = window["unique_subdomain_count"]
    unique_ratio = window["unique_query_ratio"]
    us_threshold = thresholds["unique_subdomain_count"]
    ur_threshold = thresholds["unique_query_ratio"]
    if subdomain_count > us_threshold and unique_ratio > ur_threshold:
        evidence.append(
            {
                "rule": RULE_HIGH_UNIQUE_SUBDOMAINS,
                "observed": subdomain_count,
                "threshold": round(us_threshold, 4),
                "reason": (
                    f"Unique subdomain count ({subdomain_count}) and unique query ratio "
                    f"({unique_ratio:.4f}) exceed normal baseline thresholds "
                    f"(subdomains: {us_threshold:.4f}, unique ratio: {ur_threshold:.4f})."
                ),
            }
        )

    # E. HIGH_NXDOMAIN_RATIO
    nxdomain_ratio = window["nxdomain_ratio"]
    nx_threshold = thresholds["nxdomain_ratio"]
    if nxdomain_ratio > nx_threshold:
        evidence.append(
            {
                "rule": RULE_HIGH_NXDOMAIN_RATIO,
                "observed": round(nxdomain_ratio, 4),
                "threshold": round(nx_threshold, 4),
                "reason": (
                    f"Window NXDOMAIN ratio ({nxdomain_ratio:.4f}) is above "
                    f"the normal baseline threshold ({nx_threshold:.4f})."
                ),
            }
        )

    # F. UNUSUAL_QUERY_TYPE (only evaluated if baseline has valid TXT traffic threshold)
    txt_threshold = thresholds.get("txt_ratio")
    if _is_valid_number(txt_threshold) and txt_threshold > 0.0:
        txt_ratio = _extract_txt_ratio(window)
        if txt_ratio > txt_threshold:
            evidence.append(
                {
                    "rule": RULE_UNUSUAL_QUERY_TYPE,
                    "observed": round(txt_ratio, 4),
                    "threshold": round(txt_threshold, 4),
                    "reason": (
                        f"Window TXT query ratio ({txt_ratio:.4f}) is above "
                        f"the normal baseline TXT threshold ({txt_threshold:.4f})."
                    ),
                }
            )

    return evidence


def detect_window(
    window: dict,
    baseline: dict,
    min_correlated_signals: int = MIN_CORRELATED_SIGNALS,
) -> dict:
    """
    Evaluate a single behavioral window against the baseline and apply multi-signal correlation.

    A window is classified as `suspicious = True` only when at least `min_correlated_signals`
    (default 2) independent weak behavioral indicators are triggered.
    """
    if not is_valid_window(window):
        return {
            "source_ip": (
                window.get("source_ip")
                if isinstance(window, dict) and isinstance(window.get("source_ip"), str)
                else None
            ),
            "window_start": (
                window.get("window_start")
                if isinstance(window, dict) and _is_valid_number(window.get("window_start"))
                else None
            ),
            "window_end": (
                window.get("window_end")
                if isinstance(window, dict) and _is_valid_number(window.get("window_end"))
                else None
            ),
            "suspicious": False,
            "triggered_rules": [],
            "evidence": [],
        }

    if not _is_usable_baseline(baseline):
        return {
            "source_ip": window["source_ip"],
            "window_start": window["window_start"],
            "window_end": window["window_end"],
            "suspicious": False,
            "triggered_rules": [],
            "evidence": [],
        }

    evidence = evaluate_rules(window, baseline)
    triggered_rules = [item["rule"] for item in evidence]
    suspicious = len(triggered_rules) >= max(2, min_correlated_signals)

    return {
        "source_ip": window["source_ip"],
        "window_start": window["window_start"],
        "window_end": window["window_end"],
        "suspicious": suspicious,
        "triggered_rules": triggered_rules,
        "evidence": evidence,
    }


def detect_windows(
    windows: list[dict],
    baseline: dict,
    min_correlated_signals: int = MIN_CORRELATED_SIGNALS,
) -> list[dict]:
    """
    Run detection across a list of aggregated windows in O(n) time, skipping malformed windows.
    """
    if not isinstance(windows, list) or not windows:
        return []

    results: list[dict] = []
    for window in windows:
        if not is_valid_window(window):
            continue
        results.append(
            detect_window(
                window,
                baseline,
                min_correlated_signals=min_correlated_signals,
            )
        )

    return results


def main() -> None:
    """Run baseline calculation and Detection Engine v1 validation on logs/normal/dns.log."""
    dns_records = read_dns_log(LOG_FILE)
    windows = aggregate_dns_records(dns_records, window_size=WINDOW_SIZE)
    baseline = calculate_baseline(windows)
    detections = detect_windows(windows, baseline)

    total_windows = len(detections)
    suspicious_windows = sum(1 for d in detections if d["suspicious"])
    suspicious_pct = (
        (suspicious_windows / total_windows) * 100.0 if total_windows > 0 else 0.0
    )

    rule_counts: Counter[str] = Counter()
    for d in detections:
        for rule in d["triggered_rules"]:
            rule_counts[rule] += 1

    print("--- Detection Engine v1: Normal Dataset Baseline & Validation ---")
    print(f"Total Aggregated Windows: {total_windows}")
    print(f"Suspicious Windows (2+ correlated signals): {suspicious_windows}")
    print(f"Percentage Suspicious: {suspicious_pct:.2f}%")
    print(f"TXT Baseline Available: {baseline['txt_baseline_available']}")

    print("\n--- Derived Baseline Thresholds ---")
    for metric, threshold in baseline["thresholds"].items():
        if threshold is None:
            print(f"  {metric}: None (insufficient baseline TXT traffic)")
        else:
            print(f"  {metric}: {threshold:.4f}")

    print("\n--- Individual Weak-Signal Trigger Counts ---")
    for rule_name in ALL_RULES:
        print(f"  {rule_name}: {rule_counts.get(rule_name, 0)}")

    windows_with_any_signal = [d for d in detections if d["triggered_rules"]]
    print(
        f"\nWindows with 1 weak signal (not classified suspicious): "
        f"{len(windows_with_any_signal) - suspicious_windows}"
    )
    if windows_with_any_signal:
        print("\n--- Sample Weak-Signal Detections (First 3) ---")
        for sample in windows_with_any_signal[:3]:
            print(json.dumps(sample, indent=4))


if __name__ == "__main__":
    main()
