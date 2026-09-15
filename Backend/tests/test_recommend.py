from orchestrator.recommend import get_recommendation


def test_recommendations_cover_known_attack_types():
    for attack_type in ("cryptominer", "port_scan", "c2_beacon", "worm_ravage"):
        recommendation = get_recommendation(attack_type)
        assert recommendation
        assert "Review" not in recommendation[:20]


def test_recommendation_falls_back_for_unknown_attack_type():
    assert get_recommendation("unknown") == (
        "Review the incident's feature vector manually; no pre-built recommendation exists "
        "for this attack signature yet."
    )