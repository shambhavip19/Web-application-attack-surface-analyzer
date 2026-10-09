from app.scanner.headers import evaluate_header_status
from app.scanner import scoring


def test_csp_frame_ancestors_is_treated_as_clickjacking_protection():
    result = evaluate_header_status(
        'x-frame-options',
        None,
        {'content-security-policy': "default-src 'self'; frame-ancestors 'none'"},
    )
    assert result['status'] in {'PASS', 'WARNING'}
    assert 'frame-ancestors' in result['explanation'].lower()


def test_score_uses_severity_based_deductions():
    result = {
        'headers': {'available': True, 'headers': {}},
        'cookies': {'available': True},
        'ssl': {'available': True, 'https': True},
        'findings': [
            {'severity': 'High', 'deduction': 10},
            {'severity': 'Low', 'deduction': 2},
        ],
    }
    score = scoring.score(result)
    assert score['score'] == 88
    assert score['level'] == 'Low'
