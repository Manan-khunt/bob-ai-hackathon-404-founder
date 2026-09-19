from typing import List, Dict, Optional
from datetime import datetime, timedelta, timezone
import re


class CorrelationEngine:
    def __init__(self):
        self.correlation_window_minutes = 5
        self.min_events_for_correlation = 2

    def compute_correlation_score(self, normalized_event: dict, recent_events: List[dict]) -> float:
        score = 0.0
        if not recent_events:
            return score

        src_ip = normalized_event.get("src_ip")
        if src_ip:
            ip_matches = sum(1 for e in recent_events if e.get("src_ip") == src_ip)
            score += min(ip_matches * 0.15, 0.45)

        severity = normalized_event.get("severity", "Medium").lower()
        sev_bonus = {"critical": 0.25, "high": 0.20, "medium": 0.10, "low": 0.05}.get(severity, 0.10)
        score += sev_bonus

        event_type = (normalized_event.get("event_type") or "").lower()
        type_bonus = 0.0
        high_correlation_types = ["lateral movement", "c2", "command and control", "privilege escalation", "credential dump", "exfiltration"]
        for ht in high_correlation_types:
            if ht in event_type:
                type_bonus = 0.20
                break
        score += type_bonus

        asset = normalized_event.get("asset") or normalized_event.get("dst_ip")
        if asset:
            asset_matches = sum(1 for e in recent_events if (e.get("asset") == asset or e.get("dst_ip") == asset))
            score += min(asset_matches * 0.08, 0.15)

        unique_sources = set()
        for e in recent_events:
            if e.get("src_ip"):
                unique_sources.add(e["src_ip"])
        if src_ip:
            unique_sources.add(src_ip)
        diversity_bonus = min(len(unique_sources) * 0.03, 0.10)
        score += diversity_bonus

        return min(round(score, 4), 1.0)

    def determine_incident(self, normalized_event: dict, correlation_score: float) -> Optional[str]:
        if correlation_score >= 0.70:
            return "new_incident"
        return None

    def assign_to_incident(self, normalized_event: dict, existing_incidents: List[dict]) -> Optional[str]:
        src_ip = normalized_event.get("src_ip")
        if not src_ip:
            return None

        best_match = None
        best_score = 0.0

        for inc in existing_incidents:
            if inc.get("status") in ("RESOLVED", "FALSE_POSITIVE"):
                continue
            score = 0.0
            inc_assets = inc.get("affected_assets", [])
            for asset_entry in inc_assets:
                if asset_entry.get("asset_ip") == src_ip:
                    score += 0.5
                    break

            inc_sources = inc.get("sources", [])
            if normalized_event.get("source") in inc_sources:
                score += 0.2

            event_type = (normalized_event.get("event_type") or "").lower()
            mitre_ids = inc.get("mitre_ids", [])
            related_ttps = ["lateral movement", "c2", "command and control", "privilege escalation", "credential dump"]
            for ttp in related_ttps:
                if ttp in event_type:
                    score += 0.3
                    break

            if score > best_score and score >= 0.4:
                best_score = score
                best_match = inc.get("id")

        return best_match

    def filter_events_in_window(self, events: List[dict], window_minutes: Optional[int] = None) -> List[dict]:
        if not events:
            return []
        window = window_minutes or self.correlation_window_minutes
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=window)
        return [
            e for e in events
            if e.get("created_at") and e["created_at"] >= cutoff
        ]
