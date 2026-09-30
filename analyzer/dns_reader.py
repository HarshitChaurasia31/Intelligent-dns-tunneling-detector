from collections import Counter
import json
from math import log2

LOG_FILE = "logs/normal/dns.log"
WINDOW_SIZE = 10  # seconds
SAMPLE_FEATURE_COUNT = 5
TOP_SUBDOMAIN_LIMIT = 10


def read_dns_log(log_file: str = LOG_FILE) -> list[dict]:
    """Read Zeek JSON DNS log records from the log file safely."""
    dns_records = []
    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed JSON lines without crashing the reader
                continue

            if isinstance(record, dict):
                dns_records.append(record)

    return dns_records


def calculate_entropy(value: str) -> float:
    """Calculate the Shannon entropy (in bits per character) of a string."""
    if not value or not isinstance(value, str):
        return 0.0

    total_length = len(value)
    char_counts = Counter(value)

    entropy = 0.0
    for count in char_counts.values():
        probability = count / total_length
        entropy -= probability * log2(probability)

    return round(entropy, 4)


def extract_basic_features(record: dict) -> dict:
    """Extract basic DNS features (including longest-label entropy) from a single Zeek DNS record."""
    raw_query = record.get("query")
    query = raw_query.strip() if isinstance(raw_query, str) else ""

    if query:
        query_length = len(query)
        # Filter out empty labels to safely handle leading/trailing or consecutive dots
        labels = [label for label in query.split(".") if label]
        if labels:
            # Deterministic selection: max(..., key=len) picks the first longest label on ties
            longest_label = max(labels, key=len)
            max_label_length = len(longest_label)
            entropy = calculate_entropy(longest_label)
        else:
            max_label_length = 0
            entropy = 0.0
    else:
        query_length = 0
        max_label_length = 0
        entropy = 0.0

    return {
        "timestamp": record.get("ts"),
        "source_ip": record.get("id.orig_h"),
        "destination_ip": record.get("id.resp_h"),
        "query": query,
        "query_length": query_length,
        "max_label_length": max_label_length,
        "query_type": record.get("qtype_name"),
        "response_code": record.get("rcode_name"),
        "entropy": entropy,
    }


def extract_features(dns_records: list[dict]) -> list[dict]:
    """Build a list of structured feature dictionaries for all valid DNS records."""
    features = []
    for record in dns_records:
        if not isinstance(record, dict):
            continue
        features.append(extract_basic_features(record))
    return features


def calculate_query_frequency(dns_records: list[dict]) -> dict[str, dict[int, int]]:
    """Count DNS queries per source IP within fixed 10-second time windows."""
    query_counts: dict[str, dict[int, int]] = {}

    for record in dns_records:
        if not isinstance(record, dict):
            continue

        ip = record.get("id.orig_h")
        ts = record.get("ts")

        # Require a valid source IP and numeric timestamp (excluding booleans)
        if not ip or not isinstance(ts, (int, float)) or isinstance(ts, bool):
            continue

        window = int(ts // WINDOW_SIZE)

        if ip not in query_counts:
            query_counts[ip] = {}
        ip_windows = query_counts[ip]
        ip_windows[window] = ip_windows.get(window, 0) + 1

    return query_counts


def calculate_unique_subdomains(features: list[dict]) -> dict[str, dict[str, set[str]]]:
    """Track unique subdomains per (source_ip, parent_domain) using sets."""
    unique_subdomains: dict[str, dict[str, set[str]]] = {}

    for feature in features:
        if not isinstance(feature, dict):
            continue

        source_ip = feature.get("source_ip")
        query = feature.get("query")

        if not source_ip or not isinstance(query, str):
            continue

        clean_query = query.strip().strip(".")
        if not clean_query:
            continue

        parts = clean_query.split(".")
        # Ignore malformed queries (empty labels) or queries without a subdomain (e.g. example.com)
        if len(parts) < 3 or any(not part for part in parts):
            continue

        parent_domain = ".".join(parts[-2:])
        subdomain = ".".join(parts[:-2])

        if source_ip not in unique_subdomains:
            unique_subdomains[source_ip] = {}
        ip_domains = unique_subdomains[source_ip]

        if parent_domain not in ip_domains:
            ip_domains[parent_domain] = set()
        ip_domains[parent_domain].add(subdomain)

    return unique_subdomains


def calculate_nxdomain_ratio(dns_records: list[dict]) -> float:
    """Calculate the ratio of NXDOMAIN responses across all DNS records."""
    if not dns_records:
        return 0.0

    total_queries = len(dns_records)
    nxdomain_count = 0

    for record in dns_records:
        if isinstance(record, dict) and record.get("rcode_name") == "NXDOMAIN":
            nxdomain_count += 1

    return nxdomain_count / total_queries


def calculate_average_query_length(dns_records: list[dict]) -> float:
    """Calculate the average length of valid DNS query strings across all DNS records."""
    if not dns_records:
        return 0.0

    total_length = 0
    valid_query_count = 0

    for record in dns_records:
        if not isinstance(record, dict):
            continue

        query = record.get("query")
        if isinstance(query, str):
            total_length += len(query)
            valid_query_count += 1

    if valid_query_count == 0:
        return 0.0

    return total_length / valid_query_count


def calculate_unique_query_ratio(dns_records: list[dict]) -> float:
    """Calculate the ratio of distinct DNS query names to total valid DNS queries."""
    if not dns_records:
        return 0.0

    unique_queries: set[str] = set()
    valid_query_count = 0

    for record in dns_records:
        if not isinstance(record, dict):
            continue

        query = record.get("query")
        if isinstance(query, str):
            unique_queries.add(query)
            valid_query_count += 1

    if valid_query_count == 0:
        return 0.0

    return len(unique_queries) / valid_query_count


def calculate_repeated_query_ratio(dns_records: list[dict]) -> float:
    """Calculate the ratio of repeated DNS query names across valid DNS records."""
    unique_query_ratio = calculate_unique_query_ratio(dns_records)
    if unique_query_ratio == 0.0:
        return 0.0

    return 1.0 - unique_query_ratio


def calculate_dns_persistence(dns_records: list[dict]) -> float:
    """Calculate DNS activity persistence duration (latest_ts - earliest_ts) in seconds."""
    if not dns_records:
        return 0.0

    earliest_timestamp: float | None = None
    latest_timestamp: float | None = None

    for record in dns_records:
        if not isinstance(record, dict):
            continue

        ts = record.get("ts")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            continue

        if earliest_timestamp is None or ts < earliest_timestamp:
            earliest_timestamp = ts
        if latest_timestamp is None or ts > latest_timestamp:
            latest_timestamp = ts

    if earliest_timestamp is None or latest_timestamp is None:
        return 0.0

    return float(latest_timestamp - earliest_timestamp)


def main() -> None:
    """Run DNS log feature extraction, query frequency, unique subdomain, NXDOMAIN, query length, repetition, and persistence analysis."""
    dns_records = read_dns_log()
    print(f"Total DNS records:{len(dns_records)}")

    # 1. Extract basic features (including longest-label Shannon entropy) for every DNS record
    features = extract_features(dns_records)
    print(f"Total Feature records:{len(features)}")

    print(f"\n--- Basic DNS Features (First {SAMPLE_FEATURE_COUNT} Records) ---")
    for feature in features[:SAMPLE_FEATURE_COUNT]:
        print(json.dumps(feature, indent=4))

    print("\n--- Entropy Summary ---")
    if features:
        entropies = [feature["entropy"] for feature in features]
        min_entropy = min(entropies)
        max_entropy = max(entropies)
        avg_entropy = sum(entropies) / len(entropies)
    else:
        min_entropy = 0.0
        max_entropy = 0.0
        avg_entropy = 0.0
    print(f"Minimum Entropy: {min_entropy:.4f}")
    print(f"Maximum Entropy: {max_entropy:.4f}")
    print(f"Average Entropy: {avg_entropy:.4f}")

    # 2. Calculate query frequency per source IP and 10-second window
    query_counts = calculate_query_frequency(dns_records)
    print("\n--- Query Frequency ---")
    for ip, windows in query_counts.items():
        print(f"\nSource IP: {ip}")
        total_queries = 0
        max_queries_per_second = 0.0
        for window, count in sorted(windows.items()):
            queries_per_second = count / WINDOW_SIZE
            total_queries += count
            if queries_per_second > max_queries_per_second:
                max_queries_per_second = queries_per_second
            print(
                f"Window {window}: "
                f"{count} queries ->"
                f"{queries_per_second:.2f} queries/sec"
            )
        print(f"Total Queries: {total_queries}")
        print(f"Maximum Query Rate: {max_queries_per_second:.2f} queries/sec")

    # 3. Calculate unique subdomains per source IP and parent domain
    unique_subdomains = calculate_unique_subdomains(features)
    print("\n--- Unique Subdomains ---")
    for source_ip, domains in unique_subdomains.items():
        # Sort domains by unique subdomain count (highest first) and display top sample
        sorted_domains = sorted(
            domains.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        )
        for domain, subdomains in sorted_domains[:TOP_SUBDOMAIN_LIMIT]:
            print(f"\nSource IP: {source_ip}")
            print(f"Domain: {domain}")
            print(f"Unique Subdomains: {len(subdomains)}")

    # 4. Calculate NXDOMAIN ratio across the dataset
    total_queries = len(dns_records)
    nxdomain_count = sum(
        1
        for record in dns_records
        if isinstance(record, dict) and record.get("rcode_name") == "NXDOMAIN"
    )
    nxdomain_ratio = calculate_nxdomain_ratio(dns_records)

    print("\n--- NXDOMAIN Analysis ---")
    print(f"Total DNS Queries: {total_queries}")
    print(f"NXDOMAIN Queries: {nxdomain_count}")
    print(f"NXDOMAIN Ratio: {nxdomain_ratio:.4f}")

    # 5. Calculate average query length across the dataset
    avg_query_length = calculate_average_query_length(dns_records)

    print("\n--- Query Length Analysis ---")
    print(f"Average Query Length: {avg_query_length:.4f}")

    # 6. Calculate unique vs repeated query ratios across the dataset
    valid_queries = [
        record["query"]
        for record in dns_records
        if isinstance(record, dict) and isinstance(record.get("query"), str)
    ]
    total_valid_queries = len(valid_queries)
    unique_query_count = len(set(valid_queries))
    unique_query_ratio = calculate_unique_query_ratio(dns_records)
    repeated_query_ratio = calculate_repeated_query_ratio(dns_records)

    print("\n--- Query Repetition Analysis ---")
    print(f"Total Valid Queries: {total_valid_queries}")
    print(f"Unique Queries: {unique_query_count}")
    print(f"Unique Query Ratio: {unique_query_ratio:.4f}")
    print(f"Repeated Query Ratio: {repeated_query_ratio:.4f}")

    # 7. Calculate DNS activity persistence duration across the dataset
    persistence_duration = calculate_dns_persistence(dns_records)

    print("\n--- DNS Persistence Analysis ---")
    print(f"Persistence Duration: {persistence_duration:.4f} seconds")


if __name__ == "__main__":
    main()







