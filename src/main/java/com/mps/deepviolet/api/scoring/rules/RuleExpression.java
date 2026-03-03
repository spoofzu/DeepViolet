package com.mps.deepviolet.api.scoring.rules;

import java.util.List;

/**
 * AST nodes for the rule expression DSL.
 * Evaluated by {@link RuleExpressionEvaluator} against a {@link RuleContext}.
 */
public sealed interface RuleExpression {

	record Literal(Object value) implements RuleExpression {}

	record PropertyRef(List<String> path) implements RuleExpression {}

	record Comparison(RuleExpression left, String operator, RuleExpression right) implements RuleExpression {}

	record And(RuleExpression left, RuleExpression right) implements RuleExpression {}

	record Or(RuleExpression left, RuleExpression right) implements RuleExpression {}

	record Not(RuleExpression operand) implements RuleExpression {}

	record Contains(RuleExpression collection, RuleExpression element, boolean negated) implements RuleExpression {}

	record FunctionCall(String name, List<RuleExpression> args) implements RuleExpression {}

	/** count(list, filterField op filterValue) — filtered count over a list of maps. */
	record CountFiltered(RuleExpression list, String filterField, String filterOp, RuleExpression filterValue)
			implements RuleExpression {}
}
