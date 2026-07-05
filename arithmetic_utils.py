"""Small safe arithmetic evaluator for example tools."""

from __future__ import annotations

import ast
import operator
from typing import Callable


_BINARY_OPERATORS: dict[type[ast.operator], Callable[[float, float], float]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
}
_UNARY_OPERATORS: dict[type[ast.unaryop], Callable[[float], float]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def evaluate_arithmetic_expression(expression: str) -> int | float:
    """Evaluate a bounded arithmetic expression without executing Python code."""
    tree = ast.parse(expression, mode="eval")
    return _evaluate_node(tree.body)


def _evaluate_node(node: ast.AST) -> int | float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp):
        operator_fn = _BINARY_OPERATORS.get(type(node.op))
        if operator_fn is None:
            raise ValueError("unsupported operator")
        return operator_fn(_evaluate_node(node.left), _evaluate_node(node.right))
    if isinstance(node, ast.UnaryOp):
        operator_fn = _UNARY_OPERATORS.get(type(node.op))
        if operator_fn is None:
            raise ValueError("unsupported unary operator")
        return operator_fn(_evaluate_node(node.operand))
    raise ValueError("expression must contain only numbers and arithmetic operators")
