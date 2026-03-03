package com.mps.deepviolet.api.scoring.rules;

import java.util.ArrayList;
import java.util.List;

/**
 * Recursive descent parser for the rule expression DSL.
 * Parses a string expression into a {@link RuleExpression} AST.
 *
 * <pre>
 * Grammar:
 *   expression  = or_expr
 *   or_expr     = and_expr ( "or" and_expr )*
 *   and_expr    = not_expr ( "and" not_expr )*
 *   not_expr    = "not" not_expr | comparison
 *   comparison  = value ( comp_op value | "contains" value | "not" "contains" value )?
 *   comp_op     = "==" | "!=" | "&lt;" | "&gt;" | "&lt;=" | "&gt;="
 *   value       = function_call | property_path | literal | "(" expression ")"
 *   function    = IDENT "(" args ")"
 *                | IDENT "(" list "," filter_expr ")"
 *   literal     = STRING | INTEGER | "true" | "false" | "null"
 *   property    = IDENT ( "." IDENT )*
 * </pre>
 */
public class RuleExpressionParser {

	private final String input;
	private final List<Token> tokens;
	private int pos;

	private enum TokenType {
		IDENT, STRING, INTEGER, LPAREN, RPAREN, COMMA,
		EQ, NEQ, LT, GT, LTE, GTE, DOT, EOF
	}

	private record Token(TokenType type, String value, int position) {}

	public RuleExpressionParser(String input) {
		this.input = input;
		this.tokens = tokenize(input);
		this.pos = 0;
	}

	/**
	 * Parse the input expression string.
	 * @param input Expression string
	 * @return Parsed AST
	 * @throws IllegalArgumentException on parse errors
	 */
	public static RuleExpression parse(String input) {
		if (input == null || input.isBlank()) {
			throw new IllegalArgumentException("Expression cannot be null or blank");
		}
		RuleExpressionParser parser = new RuleExpressionParser(input.strip());
		RuleExpression expr = parser.parseExpression();
		if (parser.pos < parser.tokens.size() && parser.peek().type != TokenType.EOF) {
			throw parser.error("Unexpected token after expression: " + parser.peek().value);
		}
		return expr;
	}

	private RuleExpression parseExpression() {
		return parseOr();
	}

	private RuleExpression parseOr() {
		RuleExpression left = parseAnd();
		while (isKeyword("or")) {
			consume(); // eat "or"
			RuleExpression right = parseAnd();
			left = new RuleExpression.Or(left, right);
		}
		return left;
	}

	private RuleExpression parseAnd() {
		RuleExpression left = parseNot();
		while (isKeyword("and")) {
			consume(); // eat "and"
			RuleExpression right = parseNot();
			left = new RuleExpression.And(left, right);
		}
		return left;
	}

	private RuleExpression parseNot() {
		if (isKeyword("not")) {
			consume(); // eat "not"
			// Check for "not contains" — handled in comparison
			// If next is not "contains", it's a prefix not
			RuleExpression operand = parseNot();
			return new RuleExpression.Not(operand);
		}
		return parseComparison();
	}

	private RuleExpression parseComparison() {
		RuleExpression left = parseValue();

		if (pos < tokens.size()) {
			Token next = peek();
			// Comparison operators
			if (isComparisonOp(next.type)) {
				String op = consume().value;
				RuleExpression right = parseValue();
				return new RuleExpression.Comparison(left, op, right);
			}
			// "contains" keyword
			if (isKeyword("contains")) {
				consume(); // eat "contains"
				RuleExpression right = parseValue();
				return new RuleExpression.Contains(left, right, false);
			}
			// "not contains" — left not contains right
			if (isKeyword("not") && isKeywordAt(pos + 1, "contains")) {
				consume(); // eat "not"
				consume(); // eat "contains"
				RuleExpression right = parseValue();
				return new RuleExpression.Contains(left, right, true);
			}
		}

		return left;
	}

	private RuleExpression parseValue() {
		Token token = peek();

		// Parenthesized expression
		if (token.type == TokenType.LPAREN) {
			consume(); // eat "("
			RuleExpression expr = parseExpression();
			expect(TokenType.RPAREN, ")");
			return expr;
		}

		// String literal
		if (token.type == TokenType.STRING) {
			consume();
			return new RuleExpression.Literal(token.value);
		}

		// Integer literal
		if (token.type == TokenType.INTEGER) {
			consume();
			return new RuleExpression.Literal(Long.parseLong(token.value));
		}

		// Keywords: true, false, null
		if (token.type == TokenType.IDENT) {
			if ("true".equals(token.value)) {
				consume();
				return new RuleExpression.Literal(Boolean.TRUE);
			}
			if ("false".equals(token.value)) {
				consume();
				return new RuleExpression.Literal(Boolean.FALSE);
			}
			if ("null".equals(token.value)) {
				consume();
				return new RuleExpression.Literal(null);
			}

			// Function call: IDENT "(" ... ")"
			if (pos + 1 < tokens.size() && tokens.get(pos + 1).type == TokenType.LPAREN) {
				return parseFunctionCall();
			}

			// Property path: IDENT ( "." IDENT )*
			return parsePropertyPath();
		}

		throw error("Unexpected token: " + token.value);
	}

	private RuleExpression parseFunctionCall() {
		String funcName = consume().value; // function name
		expect(TokenType.LPAREN, "(");

		if (peek().type == TokenType.RPAREN) {
			consume(); // eat ")"
			return new RuleExpression.FunctionCall(funcName, List.of());
		}

		// Special handling for count(list, field op value)
		if ("count".equals(funcName)) {
			RuleExpression firstArg = parseExpression();
			if (peek().type == TokenType.COMMA) {
				consume(); // eat ","
				// Parse filter: field op value
				return parseCountFiltered(firstArg);
			}
			// count(list) — no filter
			expect(TokenType.RPAREN, ")");
			return new RuleExpression.FunctionCall("count", List.of(firstArg));
		}

		// Regular function call
		List<RuleExpression> args = new ArrayList<>();
		args.add(parseExpression());
		while (peek().type == TokenType.COMMA) {
			consume(); // eat ","
			args.add(parseExpression());
		}
		expect(TokenType.RPAREN, ")");
		return new RuleExpression.FunctionCall(funcName, args);
	}

	private RuleExpression parseCountFiltered(RuleExpression list) {
		// Expect: field op value
		if (peek().type != TokenType.IDENT) {
			throw error("Expected filter field name in count(), got: " + peek().value);
		}
		String filterField = consume().value;

		// Check for string filter operators: contains, not contains, starts_with
		if (isKeyword("contains")) {
			consume(); // eat "contains"
			RuleExpression filterValue = parseValue();
			expect(TokenType.RPAREN, ")");
			return new RuleExpression.CountFiltered(list, filterField, "contains", filterValue);
		}
		if (isKeyword("not") && isKeywordAt(pos + 1, "contains")) {
			consume(); // eat "not"
			consume(); // eat "contains"
			RuleExpression filterValue = parseValue();
			expect(TokenType.RPAREN, ")");
			return new RuleExpression.CountFiltered(list, filterField, "not contains", filterValue);
		}
		if (isKeyword("starts_with")) {
			consume(); // eat "starts_with"
			RuleExpression filterValue = parseValue();
			expect(TokenType.RPAREN, ")");
			return new RuleExpression.CountFiltered(list, filterField, "starts_with", filterValue);
		}

		Token opToken = peek();
		if (!isComparisonOp(opToken.type)) {
			throw error("Expected comparison operator in count() filter, got: " + opToken.value);
		}
		String filterOp = consume().value;
		RuleExpression filterValue = parseValue();
		expect(TokenType.RPAREN, ")");
		return new RuleExpression.CountFiltered(list, filterField, filterOp, filterValue);
	}

	private RuleExpression parsePropertyPath() {
		List<String> path = new ArrayList<>();
		path.add(consume().value);
		while (pos < tokens.size() && peek().type == TokenType.DOT) {
			consume(); // eat "."
			Token next = peek();
			if (next.type != TokenType.IDENT) {
				throw error("Expected identifier after '.', got: " + next.value);
			}
			path.add(consume().value);
		}
		return new RuleExpression.PropertyRef(path);
	}

	// --- Token helpers ---

	private Token peek() {
		if (pos >= tokens.size()) {
			return new Token(TokenType.EOF, "<EOF>", input.length());
		}
		return tokens.get(pos);
	}

	private Token consume() {
		Token t = peek();
		if (t.type == TokenType.EOF) {
			throw error("Unexpected end of expression");
		}
		pos++;
		return t;
	}

	private void expect(TokenType type, String display) {
		Token t = peek();
		if (t.type != type) {
			throw error("Expected '" + display + "', got: " + t.value);
		}
		consume();
	}

	private boolean isKeyword(String keyword) {
		Token t = peek();
		return t.type == TokenType.IDENT && keyword.equals(t.value);
	}

	private boolean isKeywordAt(int index, String keyword) {
		if (index >= tokens.size()) return false;
		Token t = tokens.get(index);
		return t.type == TokenType.IDENT && keyword.equals(t.value);
	}

	private boolean isComparisonOp(TokenType type) {
		return type == TokenType.EQ || type == TokenType.NEQ
				|| type == TokenType.LT || type == TokenType.GT
				|| type == TokenType.LTE || type == TokenType.GTE;
	}

	private IllegalArgumentException error(String message) {
		return new IllegalArgumentException("Parse error at position " + pos + ": " + message
				+ " [input: " + input + "]");
	}

	// --- Tokenizer ---

	private static List<Token> tokenize(String input) {
		List<Token> tokens = new ArrayList<>();
		int i = 0;
		int len = input.length();

		while (i < len) {
			char c = input.charAt(i);

			// Skip whitespace
			if (Character.isWhitespace(c)) {
				i++;
				continue;
			}

			// Two-character operators
			if (i + 1 < len) {
				String two = input.substring(i, i + 2);
				TokenType twoType = switch (two) {
					case "==" -> TokenType.EQ;
					case "!=" -> TokenType.NEQ;
					case "<=" -> TokenType.LTE;
					case ">=" -> TokenType.GTE;
					default -> null;
				};
				if (twoType != null) {
					tokens.add(new Token(twoType, two, i));
					i += 2;
					continue;
				}
			}

			// Single-character operators/delimiters
			TokenType singleType = switch (c) {
				case '<' -> TokenType.LT;
				case '>' -> TokenType.GT;
				case '(' -> TokenType.LPAREN;
				case ')' -> TokenType.RPAREN;
				case ',' -> TokenType.COMMA;
				case '.' -> TokenType.DOT;
				default -> null;
			};
			if (singleType != null) {
				tokens.add(new Token(singleType, String.valueOf(c), i));
				i++;
				continue;
			}

			// String literal (double-quoted)
			if (c == '"') {
				int start = i;
				i++; // skip opening quote
				StringBuilder sb = new StringBuilder();
				while (i < len && input.charAt(i) != '"') {
					if (input.charAt(i) == '\\' && i + 1 < len) {
						i++; // skip escape char
					}
					sb.append(input.charAt(i));
					i++;
				}
				if (i >= len) {
					throw new IllegalArgumentException("Unterminated string literal at position " + start);
				}
				i++; // skip closing quote
				tokens.add(new Token(TokenType.STRING, sb.toString(), start));
				continue;
			}

			// Integer literal (including negative)
			if (Character.isDigit(c) || (c == '-' && i + 1 < len && Character.isDigit(input.charAt(i + 1)))) {
				int start = i;
				if (c == '-') i++;
				while (i < len && Character.isDigit(input.charAt(i))) {
					i++;
				}
				tokens.add(new Token(TokenType.INTEGER, input.substring(start, i), start));
				continue;
			}

			// Identifier or keyword
			if (Character.isLetter(c) || c == '_') {
				int start = i;
				while (i < len && (Character.isLetterOrDigit(input.charAt(i)) || input.charAt(i) == '_')) {
					i++;
				}
				tokens.add(new Token(TokenType.IDENT, input.substring(start, i), start));
				continue;
			}

			throw new IllegalArgumentException("Unexpected character '" + c + "' at position " + i
					+ " in expression: " + input);
		}

		return tokens;
	}
}
