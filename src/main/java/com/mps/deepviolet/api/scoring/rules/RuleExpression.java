package com.mps.deepviolet.api.scoring.rules;

import java.util.List;

/**
 * AST nodes for the rule expression DSL.
 * Evaluated by {@link RuleExpressionEvaluator} against a {@link RuleContext}.
 */
public sealed interface RuleExpression {

	/** A literal value (string, number, boolean, null).
	 *  @param value the literal value */
	record Literal(Object value) implements RuleExpression {}

	/** A property reference resolved against the rule context.
	 *  @param path dotted property path segments */
	record PropertyRef(List<String> path) implements RuleExpression {}

	/** A comparison between two expressions.
	 *  @param left left operand
	 *  @param operator comparison operator
	 *  @param right right operand */
	record Comparison(RuleExpression left, String operator, RuleExpression right) implements RuleExpression {}

	/** Logical AND of two expressions.
	 *  @param left left operand
	 *  @param right right operand */
	record And(RuleExpression left, RuleExpression right) implements RuleExpression {}

	/** Logical OR of two expressions.
	 *  @param left left operand
	 *  @param right right operand */
	record Or(RuleExpression left, RuleExpression right) implements RuleExpression {}

	/** Logical NOT of an expression.
	 *  @param operand the operand to negate */
	record Not(RuleExpression operand) implements RuleExpression {}

	/** Collection contains/not-contains check.
	 *  @param collection collection expression
	 *  @param element element expression
	 *  @param negated true for "not contains" */
	record Contains(RuleExpression collection, RuleExpression element, boolean negated) implements RuleExpression {}

	/** A named function call with arguments.
	 *  @param name function name
	 *  @param args function arguments */
	record FunctionCall(String name, List<RuleExpression> args) implements RuleExpression {}

	/**
	 * count(list, filterField op filterValue) — filtered count over a list of maps.
	 *
	 * @param list        expression resolving to the list to count over
	 * @param filterField field name to test within each map entry
	 * @param filterOp    comparison operator (e.g. {@code "=="}, {@code "!="})
	 * @param filterValue expression resolving to the value to compare against
	 */
	record CountFiltered(RuleExpression list, String filterField, String filterOp, RuleExpression filterValue)
			implements RuleExpression {}
}
