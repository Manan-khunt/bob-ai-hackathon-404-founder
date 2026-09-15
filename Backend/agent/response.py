"""Local response path that does not require an orchestrator round trip."""

from agent.immunity import ImmunityStore


def defend_locally(store: ImmunityStore, frame: dict, scenario: str) -> dict:
    antibody = store.match(scenario)
    if not antibody:
        return {**frame, "gen": "normal"}
    return {
        **frame,
        "gen": "self_defense_triggered",
        "neutral_action": antibody["neutral_action"],
        "antibody_id": antibody["antibody_id"],
    }
