import pytest

from arithmetic_utils import evaluate_arithmetic_expression


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("(3 + 4) * 2", 14),
        ("-2 ** 3", -8),
        ("7 / 2", 3.5),
        ("2 ** 4", 16),
    ],
)
def test_evaluate_arithmetic_expression(expression, expected):
    assert evaluate_arithmetic_expression(expression) == expected


@pytest.mark.parametrize(
    "expression",
    [
        '__import__("os").system("id")',
        "value + 1",
        "[1, 2, 3]",
        "2 < 3",
        "True",
    ],
)
def test_evaluate_arithmetic_expression_rejects_non_arithmetic(expression):
    with pytest.raises(ValueError):
        evaluate_arithmetic_expression(expression)
