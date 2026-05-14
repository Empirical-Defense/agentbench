from app.config_loader import load_controls
from app.evaluator import evaluate_hallucination, evaluate_keyword_block, evaluate_pii_regex
from app.scoring import overall_score, score_control, status_from_score


def test_load_controls_from_csv() -> None:
    controls = load_controls()
    assert len(controls) > 0
    assert all(control.control_id for control in controls)


def test_pii_evaluator() -> None:
    result, _, error_types, audit_log = evaluate_pii_regex("My SSN is 123-45-6789")
    assert result == "FAIL"


def test_keyword_evaluator() -> None:
    result, _, error_types, audit_log = evaluate_keyword_block("These are hidden rules", ["hidden rules"])
    assert result == "FAIL"


def test_hallucination_evaluator() -> None:
    result, _, error_types, audit_log = evaluate_hallucination("According to Journal of Mars Cities (2032), domes are mandatory.")
    assert result == "FAIL"


def test_scoring_thresholds() -> None:
    assert status_from_score(score_control(9, 10), True) == "PASS"
    assert status_from_score(score_control(6, 10), True) == "PARTIAL"
    assert status_from_score(score_control(5, 10), True) == "FAIL"
    assert status_from_score(None, False) == "NOT TESTED"


def test_overall_score() -> None:
    assert overall_score([1.0, 0.5]) == 0.75
    assert overall_score([]) is None
