"""
Streamlit SOC Dashboard V1 for the Intelligent DNS Tunneling Detection
and Incident Response System.

Run with:
    python -m streamlit run frontend/app.py

Architecture:
    Streamlit -> FastAPI -> PostgreSQL
"""

import os
import sys
from typing import Any

import streamlit as st

# Ensure project root is on sys.path when launched via `streamlit run frontend/app.py`
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from frontend.api_client import (
    APIClientError,
    APIUnavailableError,
    API_UNAVAILABLE_MESSAGE,
    MONITORING_STATUS_V1,
    build_incident_table_rows,
    compute_incident_summary,
    fetch_health,
    fetch_incident_by_id,
    fetch_incident_count,
    fetch_incidents,
    get_api_base_url,
)

SEVERITY_BADGES = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🔵 LOW",
}


def format_severity(severity: str) -> str:
    """Return a clean SOC badge label for a severity level."""
    clean = str(severity).strip().upper()
    return SEVERITY_BADGES.get(clean, clean)


def render_incident_details(incident: dict[str, Any]) -> None:
    """Render detailed investigation view for the selected SOC incident."""
    st.subheader(str(incident.get("title", "Potential DNS Tunneling Activity")))

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.markdown(f"**Incident ID:** `{incident.get('incident_id', '')}`")
        st.markdown(f"**Source IP:** `{incident.get('source_ip', '')}`")
    with col_b:
        st.markdown(f"**Severity:** {format_severity(str(incident.get('severity', '')))}")
        st.markdown(f"**Risk Score:** `{incident.get('risk_score', 0)} / 100`")
    with col_c:
        st.markdown(f"**Status:** `{incident.get('status', '')}`")
        window_start = incident.get("window_start", "")
        window_end = incident.get("window_end", "")
        st.markdown(f"**Detection Window:** `{window_start} – {window_end}`")

    st.markdown(f"**Created At:** `{incident.get('created_at', '')}`")

    st.markdown("#### Summary")
    st.info(str(incident.get("summary", "")))

    rules_col, breakdown_col = st.columns(2)
    with rules_col:
        st.markdown("#### Triggered Rules")
        triggered_rules = incident.get("triggered_rules", [])
        if triggered_rules:
            for rule in triggered_rules:
                st.markdown(f"- `{rule}`")
        else:
            st.caption("No triggered rules recorded.")

    with breakdown_col:
        st.markdown("#### Score Breakdown")
        score_breakdown = incident.get("score_breakdown", {})
        if isinstance(score_breakdown, dict) and score_breakdown:
            breakdown_rows = [
                {"Rule": str(rule), "Points": points}
                for rule, points in score_breakdown.items()
            ]
            st.dataframe(breakdown_rows, width="stretch", hide_index=True)
        else:
            st.caption("No score breakdown recorded.")

    with st.expander("Evidence Details", expanded=True):
        evidence_list = incident.get("evidence", [])
        if isinstance(evidence_list, list) and evidence_list:
            evidence_rows = [
                {
                    "Rule": str(item.get("rule", "")),
                    "Observed": item.get("observed", ""),
                    "Threshold": item.get("threshold", ""),
                    "Reason": str(item.get("reason", "")),
                }
                for item in evidence_list
                if isinstance(item, dict)
            ]
            st.dataframe(evidence_rows, width="stretch", hide_index=True)
        else:
            st.caption("No evidence items available.")

    st.markdown("#### Recommended Investigation Actions")
    investigation = incident.get("investigation", {})
    actions = (
        investigation.get("recommended_actions", [])
        if isinstance(investigation, dict)
        else []
    )
    if isinstance(actions, list) and actions:
        for action in actions:
            st.markdown(f"- {action}")
    else:
        st.caption("No investigation actions available.")


def main() -> None:
    """Render the Streamlit SOC Dashboard V1."""
    st.set_page_config(
        page_title="DNS Tunneling Detection SOC",
        layout="wide",
    )

    header_col, action_col = st.columns([4, 1])
    with header_col:
        st.title("DNS Tunneling Detection SOC")
        st.caption(
            f"SOC Analyst Console (V1) • FastAPI Backend: `{get_api_base_url()}`"
        )
    with action_col:
        st.write("")
        if st.button("Refresh Data", width="stretch"):
            st.rerun()

    # Check API health and load incidents via FastAPI
    try:
        fetch_health()
        api_count = fetch_incident_count()
        incidents = fetch_incidents()
    except APIUnavailableError:
        st.subheader("System Status")
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("API Status", "Offline")
        s2.metric("Monitoring Status", MONITORING_STATUS_V1)
        s3.metric("Total Incidents", "—")
        s4.metric("Critical Incidents", "—")
        st.error(API_UNAVAILABLE_MESSAGE)
        return
    except APIClientError as exc:
        st.subheader("System Status")
        s1, s2, s3, s4 = st.columns(4)
        s1.metric("API Status", "Error")
        s2.metric("Monitoring Status", MONITORING_STATUS_V1)
        s3.metric("Total Incidents", "—")
        s4.metric("Critical Incidents", "—")
        st.error(f"Unable to load incident data from FastAPI: {exc}")
        return

    summary = compute_incident_summary(incidents)

    # Top Section: System Status
    st.subheader("System Status")
    sys_c1, sys_c2, sys_c3, sys_c4 = st.columns(4)
    sys_c1.metric("API Status", "Online (OK)")
    sys_c2.metric("Monitoring Status", MONITORING_STATUS_V1)
    sys_c3.metric("Total Incidents", api_count)
    sys_c4.metric("Critical Incidents", summary["critical"])

    st.divider()

    # Section 2: Incident Summary Metrics
    st.subheader("Incident Summary")
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Total Incidents", summary["total"])
    m2.metric("Critical", summary["critical"])
    m3.metric("High", summary["high"])
    m4.metric("Medium", summary["medium"])
    m5.metric("Low", summary["low"])
    m6.metric("New Status", summary["new"])

    st.divider()

    # Section 3: Incident Table
    st.subheader("Incident Table")
    if not incidents:
        st.info("No incidents are currently recorded in the system.")
        return

    table_rows = build_incident_table_rows(incidents)
    st.dataframe(table_rows, width="stretch", hide_index=True)

    st.divider()

    # Section 4: Incident Details
    st.subheader("Incident Details")
    incident_ids = [str(inc["incident_id"]) for inc in incidents]
    selected_id = st.selectbox(
        "Select an Incident ID to inspect:",
        options=incident_ids,
        index=0,
    )

    if selected_id:
        try:
            detailed_incident = fetch_incident_by_id(selected_id)
        except APIClientError as exc:
            st.error(f"Could not fetch details for {selected_id}: {exc}")
            return

        if detailed_incident is None:
            st.warning(f"Incident `{selected_id}` was not found on the server.")
        else:
            render_incident_details(detailed_incident)


if __name__ == "__main__":
    main()
