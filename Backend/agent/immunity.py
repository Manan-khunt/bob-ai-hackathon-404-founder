"""Local antibody cache and normalized rule matching."""

from datetime import datetime, timezone


class ImmunityStore:
    def __init__(self):
        self.antibodies: dict[str, dict] = {}

    def install(self, antibody: dict) -> bool:
        expires_at = antibody.get("expires_at")
        if expires_at and expires_at <= datetime.now(timezone.utc).isoformat():
            return False
        antibody_id = antibody.get("antibody_id")
        if not antibody_id:
            return False
        if antibody_id in self.antibodies:
            return False
        self.antibodies[antibody_id] = antibody
        return True

    def match(self, scenario: str) -> dict | None:
        for antibody in self.antibodies.values():
            if scenario in antibody.get("neutral_action", antibody.get("neutral_action", {})).get("match", []):
                return antibody
        return None
