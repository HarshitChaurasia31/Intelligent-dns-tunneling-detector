from math import floor, isfinite
import json

try:
    from analyzer.dns_reader import (
        LOG_FILE,
         calculate_entropy,
        read_dns_log,
    )
except ImportError:
    from dns_reader import (
        LOG_FILE,
        calculate_entropy,
        read_dns_log,
    )

WINDOW_SIZE = 10  # seconds
SAMPLE_WINDOW_COUNT = 5


def get_window_start(timestamp: int | float, window_size: int = WINDOW_SIZE) -> int:
    """Calculate the fixed time-window start timestamp using floor(timestamp / window_size) * window_size."""
    return floor(timestamp / window_size) * window_size


def extract_subdomain(query: str) -> str | None:
    """Extract the subdomain portion of a DNS query, matching dns_reader.py rules."""
    clean_query = query.strip().strip(".")
    if not clean_query:
        return None

    parts = clean_query.split(".")
    # Ignore malformed queries (empty labels) or queries without a subdomain (e.g. example.com)
    if len(parts) < 3 or any(not part for part in parts):
        return None

    return ".".join(parts[:-2])


def extract_query_entropy(query: str) -> float:
    """Calculate the Shannon entropy of the longest label in a DNS query, matching dns_reader.py."""
    labels = [label for label in query.split(".") if label]
    if not labels:
        return 0.0

    longest_label = max(labels, key=len)
    return calculate_entropy(longest_label)


def aggregate_dns_records(
    dns_records: list[dict],
    window_size: int = WINDOW_SIZE,
) -> list[dict]:
    """
    Group DNS records by (source_ip, window_start) and compute per-window behavioral statistics.

    Maintains O(n) time complexity over the input records without computing any risk or anomaly score.
    """
    if not isinstance(dns_records, list) or not dns_records:
        return []

    if (
        not isinstance(window_size, (int, float))
        or isinstance(window_size, bool)
        or window_size <= 0
    ):
        raise ValueError("window_size must be a positive number")

    windows: dict[tuple[str, int], dict] = {}

    for record in dns_records:
        if not isinstance(record, dict):
            continue

        # Validate numeric timestamp (excluding booleans, NaN, and infinity)
        ts = record.get("ts")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool) or not isfinite(ts):
            continue

        # Validate source IP
        raw_ip = record.get("id.orig_h")
        if not isinstance(raw_ip, str):
            continue
        source_ip = raw_ip.strip()
        if not source_ip:
            continue

        # Validate DNS query string
        raw_query = record.get("query")
        if not isinstance(raw_query, str):
            continue
        query = raw_query.strip()
        if not query:
            continue

        labels = [label for label in query.split(".") if label]
        if not labels:
            continue

        window_start = get_window_start(ts, window_size)
        key = (source_ip, window_start)

        query_length = len(query)
        longest_label = max(labels, key=len)
        entropy = calculate_entropy(longest_label)
        subdomain = extract_subdomain(query)
        is_nxdomain = record.get("rcode_name") == "NXDOMAIN"

        raw_qtype = record.get("qtype_name")
        qtype = (
            raw_qtype.strip()
            if isinstance(raw_qtype, str) and raw_qtype.strip()
            else None
        )

        if key not in windows:
            windows[key] = {
                "source_ip": source_ip,
                "window_start": window_start,
                "window_end": window_start + window_size,
                "total_queries": 0,
                "unique_query_set": set(),
                "total_query_length": 0,
                "maximum_query_length": 0,
                "total_entropy": 0.0,
                "maximum_entropy": 0.0,
                "unique_subdomain_set": set(),
                "nxdomain_count": 0,
                "query_types": {},
                "start_timestamp": ts,
                "end_timestamp": ts,
            }

        bucket = windows[key]
        bucket["total_queries"] += 1
        bucket["unique_query_set"].add(query)
        bucket["total_query_length"] += query_length
        if query_length > bucket["maximum_query_length"]:
            bucket["maximum_query_length"] = query_length

        bucket["total_entropy"] += entropy
        if entropy > bucket["maximum_entropy"]:
            bucket["maximum_entropy"] = entropy

        if subdomain is not None:
            bucket["unique_subdomain_set"].add(subdomain)

        if is_nxdomain:
            bucket["nxdomain_count"] += 1

        if qtype is not None:
            bucket["query_types"][qtype] = bucket["query_types"].get(qtype, 0) + 1

        if ts < bucket["start_timestamp"]:
            bucket["start_timestamp"] = ts
        if ts > bucket["end_timestamp"]:
            bucket["end_timestamp"] = ts

    aggregated_windows: list[dict] = []
    for bucket in windows.values():
        total_queries = bucket["total_queries"]
        unique_queries = len(bucket["unique_query_set"])
        unique_query_ratio = unique_queries / total_queries
        repeated_query_ratio = 1.0 - unique_query_ratio
        average_query_length = bucket["total_query_length"] / total_queries
        average_entropy = bucket["total_entropy"] / total_queries
        unique_subdomain_count = len(bucket["unique_subdomain_set"])
        nxdomain_count = bucket["nxdomain_count"]
        nxdomain_ratio = nxdomain_count / total_queries

        aggregated_windows.append(
            {
                "source_ip": bucket["source_ip"],
                "window_start": bucket["window_start"],
                "window_end": bucket["window_end"],
                "total_queries": total_queries,
                "unique_queries": unique_queries,
                "unique_query_ratio": unique_query_ratio,
                "repeated_query_ratio": repeated_query_ratio,
                "average_query_length": average_query_length,
                "maximum_query_length": bucket["maximum_query_length"],
                "average_entropy": average_entropy,
                "maximum_entropy": bucket["maximum_entropy"],
                "unique_subdomain_count": unique_subdomain_count,
                "nxdomain_count": nxdomain_count,
                "nxdomain_ratio": nxdomain_ratio,
                "query_types": bucket["query_types"],
                "start_timestamp": bucket["start_timestamp"],
                "end_timestamp": bucket["end_timestamp"],
            }
        )

    return aggregated_windows


# Convenient alias
aggregate_time_windows = aggregate_dns_records


def main() -> None:
    """Run time-windowed DNS behavioral aggregation on the normal DNS log dataset."""
    dns_records = read_dns_log(LOG_FILE)
    window_records = aggregate_dns_records(dns_records, window_size=WINDOW_SIZE)

    total_windows = len(window_records)
    total_queries = sum(window["total_queries"] for window in window_records)
    min_queries = (
        min(window["total_queries"] for window in window_records)
        if window_records
        else 0
    )
    max_queries = (
        max(window["total_queries"] for window in window_records)
        if window_records
        else 0
    )

    print("--- Time-Windowed DNS Aggregation Summary ---")
    print(f"Window Size: {WINDOW_SIZE} seconds")
    print(f"Total Input DNS Records: {len(dns_records)}")
    print(f"Total (source_ip, window_start) Groups: {total_windows}")
    print(f"Total Queries Across All Windows: {total_queries}")
    print(f"Minimum Window Query Count: {min_queries}")
    print(f"Maximum Window Query Count: {max_queries}")

    print(f"\n--- First {SAMPLE_WINDOW_COUNT} Aggregated Window Records ---")
    for window in window_records[:SAMPLE_WINDOW_COUNT]:
        print(json.dumps(window, indent=4))


if __name__ == "__main__":
    main()
