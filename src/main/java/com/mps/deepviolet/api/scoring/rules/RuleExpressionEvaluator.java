package com.mps.deepviolet.api.scoring.rules;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Evaluates a {@link RuleExpression} AST against a {@link RuleContext}.
 * Null-safe: {@code null op anything} → {@code false}, except
 * {@code == null} → {@code true} and {@code != null} → {@code false}.
 */
public class RuleExpressionEvaluator {

	private final RuleContext context;

	/**
	 * Create an evaluator for the given context.
	 * @param context the rule context to evaluate against
	 */
	public RuleExpressionEvaluator(RuleContext context) {
		this.context = context;
	}

	/**
	 * Evaluate the expression and return a boolean result.
	 * Non-boolean results are coerced: null to false, non-null to true.
	 * @param expr the expression to evaluate
	 * @return boolean result
	 */
	public boolean evaluateBoolean(RuleExpression expr) {
		Object result = evaluate(expr);
		if (result instanceof Boolean b) return b;
		return result != null;
	}

	/**
	 * Evaluate the expression and return the raw result value.
	 * @param expr the expression to evaluate
	 * @return the result value
	 */
	public Object evaluate(RuleExpression expr) {
		if (expr instanceof RuleExpression.Literal lit) {
			return lit.value();
		} else if (expr instanceof RuleExpression.PropertyRef ref) {
			return context.resolve(ref.path());
		} else if (expr instanceof RuleExpression.And and) {
			return evaluateBoolean(and.left()) && evaluateBoolean(and.right());
		} else if (expr instanceof RuleExpression.Or or) {
			return evaluateBoolean(or.left()) || evaluateBoolean(or.right());
		} else if (expr instanceof RuleExpression.Not not) {
			return !evaluateBoolean(not.operand());
		} else if (expr instanceof RuleExpression.Comparison cmp) {
			return evaluateComparison(cmp);
		} else if (expr instanceof RuleExpression.Contains cnt) {
			return evaluateContains(cnt);
		} else if (expr instanceof RuleExpression.FunctionCall fn) {
			return evaluateFunction(fn);
		} else if (expr instanceof RuleExpression.CountFiltered cf) {
			return evaluateCountFiltered(cf);
		}
		throw new IllegalArgumentException("Unknown expression type: " + expr.getClass().getName());
	}

	private boolean evaluateComparison(RuleExpression.Comparison cmp) {
		Object left = evaluate(cmp.left());
		Object right = evaluate(cmp.right());

		// Null safety: == null and != null
		if (right == null) {
			return switch (cmp.operator()) {
				case "==" -> left == null;
				case "!=" -> left != null;
				default -> false;
			};
		}
		if (left == null) {
			return switch (cmp.operator()) {
				case "==" -> false; // null == non-null
				case "!=" -> true;  // null != non-null
				default -> false;
			};
		}

		// String comparison
		if (left instanceof String ls && right instanceof String rs) {
			return switch (cmp.operator()) {
				case "==" -> ls.equals(rs);
				case "!=" -> !ls.equals(rs);
				default -> false; // strings don't support <, >, etc.
			};
		}

		// Boolean comparison
		if (left instanceof Boolean lb && right instanceof Boolean rb) {
			return switch (cmp.operator()) {
				case "==" -> lb.equals(rb);
				case "!=" -> !lb.equals(rb);
				default -> false;
			};
		}

		// Numeric comparison — coerce both to long
		Long lnum = toNumber(left);
		Long rnum = toNumber(right);
		if (lnum != null && rnum != null) {
			return switch (cmp.operator()) {
				case "==" -> lnum.longValue() == rnum.longValue();
				case "!=" -> lnum.longValue() != rnum.longValue();
				case "<" -> lnum < rnum;
				case ">" -> lnum > rnum;
				case "<=" -> lnum <= rnum;
				case ">=" -> lnum >= rnum;
				default -> false;
			};
		}

		// Cross-type == and != using toString
		return switch (cmp.operator()) {
			case "==" -> left.toString().equals(right.toString());
			case "!=" -> !left.toString().equals(right.toString());
			default -> false;
		};
	}

	@SuppressWarnings("unchecked")
	private boolean evaluateContains(RuleExpression.Contains cnt) {
		Object collection = evaluate(cnt.collection());
		Object element = evaluate(cnt.element());
		if (collection == null) return cnt.negated();

		boolean result;
		if (collection instanceof Collection<?> coll) {
			result = coll.contains(element);
			// Also try string matching for elements
			if (!result && element != null) {
				String elemStr = element.toString();
				result = coll.stream().anyMatch(e -> e != null && e.toString().equals(elemStr));
			}
		} else if (collection instanceof String str && element instanceof String sub) {
			result = str.contains(sub);
		} else {
			result = false;
		}

		return cnt.negated() ? !result : result;
	}

	private Object evaluateFunction(RuleExpression.FunctionCall fn) {
		List<RuleExpression> args = fn.args();
		return switch (fn.name()) {
			case "count" -> {
				if (args.size() != 1) throw new IllegalArgumentException("count() requires 1 argument");
				Object val = evaluate(args.get(0));
				if (val instanceof Collection<?> c) yield (long) c.size();
				if (val == null) yield 0L;
				yield 1L;
			}
			case "contains" -> {
				if (args.size() != 2) throw new IllegalArgumentException("contains() requires 2 arguments");
				Object str = evaluate(args.get(0));
				Object sub = evaluate(args.get(1));
				if (str instanceof String s && sub instanceof String ss) yield s.contains(ss);
				yield false;
			}
			case "starts_with" -> {
				if (args.size() != 2) throw new IllegalArgumentException("starts_with() requires 2 arguments");
				Object str = evaluate(args.get(0));
				Object prefix = evaluate(args.get(1));
				if (str instanceof String s && prefix instanceof String p) yield s.startsWith(p);
				yield false;
			}
			case "upper" -> {
				if (args.size() != 1) throw new IllegalArgumentException("upper() requires 1 argument");
				Object val = evaluate(args.get(0));
				yield val instanceof String s ? s.toUpperCase() : val;
			}
			case "lower" -> {
				if (args.size() != 1) throw new IllegalArgumentException("lower() requires 1 argument");
				Object val = evaluate(args.get(0));
				yield val instanceof String s ? s.toLowerCase() : val;
			}
			case "header" -> {
				if (args.size() != 1) throw new IllegalArgumentException("header() requires 1 argument");
				Object name = evaluate(args.get(0));
				if (name instanceof String headerName) {
					yield context.getHeader(headerName);
				}
				yield null;
			}
			case "header_present" -> {
				if (args.size() != 1) throw new IllegalArgumentException("header_present() requires 1 argument");
				Object name = evaluate(args.get(0));
				if (name instanceof String headerName) {
					yield context.getHeader(headerName) != null;
				}
				yield false;
			}
			case "parse_max_age" -> {
				if (args.size() != 1) throw new IllegalArgumentException("parse_max_age() requires 1 argument");
				Object val = evaluate(args.get(0));
				if (val instanceof String hstsValue) {
					yield parseMaxAge(hstsValue);
				}
				yield -1L;
			}
			default -> throw new IllegalArgumentException("Unknown function: " + fn.name());
		};
	}

	@SuppressWarnings("unchecked")
	private long evaluateCountFiltered(RuleExpression.CountFiltered cf) {
		Object listVal = evaluate(cf.list());
		if (!(listVal instanceof Collection<?> coll)) return 0L;

		Object filterValue = evaluate(cf.filterValue());
		long count = 0;

		for (Object item : coll) {
			if (item instanceof Map<?, ?> map) {
				Object fieldVal = map.get(cf.filterField());
				if (matchesFilter(fieldVal, cf.filterOp(), filterValue)) {
					count++;
				}
			}
		}
		return count;
	}

	private boolean matchesFilter(Object fieldVal, String op, Object filterValue) {
		if (fieldVal == null && filterValue == null) return "==".equals(op);
		if (fieldVal == null || filterValue == null) return "!=".equals(op);

		// Try numeric comparison
		Long fnum = toNumber(fieldVal);
		Long vnum = toNumber(filterValue);
		if (fnum != null && vnum != null) {
			return switch (op) {
				case "==" -> fnum.longValue() == vnum.longValue();
				case "!=" -> fnum.longValue() != vnum.longValue();
				case "<" -> fnum < vnum;
				case ">" -> fnum > vnum;
				case "<=" -> fnum <= vnum;
				case ">=" -> fnum >= vnum;
				default -> false;
			};
		}

		// String comparison
		String fs = fieldVal.toString();
		String vs = filterValue.toString();
		return switch (op) {
			case "==" -> fs.equals(vs);
			case "!=" -> !fs.equals(vs);
			case "contains" -> fs.contains(vs);
			case "not contains" -> !fs.contains(vs);
			case "starts_with" -> fs.startsWith(vs);
			default -> false;
		};
	}

	private static Long toNumber(Object val) {
		if (val instanceof Long l) return l;
		if (val instanceof Integer i) return (long) i;
		if (val instanceof Number n) return n.longValue();
		if (val instanceof String s) {
			try { return Long.parseLong(s); } catch (NumberFormatException e) { return null; }
		}
		return null;
	}

	private static long parseMaxAge(String hstsValue) {
		String lower = hstsValue.toLowerCase();
		int idx = lower.indexOf("max-age=");
		if (idx < 0) return -1;
		String after = hstsValue.substring(idx + 8);
		StringBuilder sb = new StringBuilder();
		for (char c : after.toCharArray()) {
			if (Character.isDigit(c)) {
				sb.append(c);
			} else {
				break;
			}
		}
		if (sb.isEmpty()) return -1;
		try {
			return Long.parseLong(sb.toString());
		} catch (NumberFormatException e) {
			return -1;
		}
	}
}
