package com.mps.deepviolet.api.scoring.rules;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Tests for the recursive descent expression parser.
 */
class RuleExpressionParserTest {

	@Test
	void testSimplePropertyPath() {
		RuleExpression expr = RuleExpressionParser.parse("session.compression_enabled");
		assertInstanceOf(RuleExpression.PropertyRef.class, expr);
		RuleExpression.PropertyRef ref = (RuleExpression.PropertyRef) expr;
		assertEquals(2, ref.path().size());
		assertEquals("session", ref.path().get(0));
		assertEquals("compression_enabled", ref.path().get(1));
	}

	@Test
	void testBooleanLiterals() {
		assertInstanceOf(RuleExpression.Literal.class, RuleExpressionParser.parse("true"));
		RuleExpression.Literal lit = (RuleExpression.Literal) RuleExpressionParser.parse("true");
		assertEquals(Boolean.TRUE, lit.value());

		lit = (RuleExpression.Literal) RuleExpressionParser.parse("false");
		assertEquals(Boolean.FALSE, lit.value());
	}

	@Test
	void testNullLiteral() {
		RuleExpression.Literal lit = (RuleExpression.Literal) RuleExpressionParser.parse("null");
		assertNull(lit.value());
	}

	@Test
	void testStringLiteral() {
		RuleExpression.Literal lit = (RuleExpression.Literal) RuleExpressionParser.parse("\"TLSv1.3\"");
		assertEquals("TLSv1.3", lit.value());
	}

	@Test
	void testIntegerLiteral() {
		RuleExpression.Literal lit = (RuleExpression.Literal) RuleExpressionParser.parse("2048");
		assertEquals(2048L, lit.value());
	}

	@Test
	void testNegativeInteger() {
		RuleExpression.Literal lit = (RuleExpression.Literal) RuleExpressionParser.parse("-1");
		assertEquals(-1L, lit.value());
	}

	@Test
	void testEqualsComparison() {
		RuleExpression expr = RuleExpressionParser.parse("cert.key_algorithm == \"RSA\"");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		RuleExpression.Comparison cmp = (RuleExpression.Comparison) expr;
		assertEquals("==", cmp.operator());
	}

	@Test
	void testNotEqualsComparison() {
		RuleExpression expr = RuleExpressionParser.parse("cert.trust_state != \"TRUSTED\"");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		assertEquals("!=", ((RuleExpression.Comparison) expr).operator());
	}

	@Test
	void testLessThanComparison() {
		RuleExpression expr = RuleExpressionParser.parse("cert.key_size < 2048");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		assertEquals("<", ((RuleExpression.Comparison) expr).operator());
	}

	@Test
	void testGreaterThanOrEqual() {
		RuleExpression expr = RuleExpressionParser.parse("cert.days_until_expiration >= 0");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		assertEquals(">=", ((RuleExpression.Comparison) expr).operator());
	}

	@Test
	void testContains() {
		RuleExpression expr = RuleExpressionParser.parse("protocols contains \"SSLv2\"");
		assertInstanceOf(RuleExpression.Contains.class, expr);
		RuleExpression.Contains cnt = (RuleExpression.Contains) expr;
		assertFalse(cnt.negated());
	}

	@Test
	void testNotContains() {
		RuleExpression expr = RuleExpressionParser.parse("protocols not contains \"TLSv1.3\"");
		assertInstanceOf(RuleExpression.Contains.class, expr);
		assertTrue(((RuleExpression.Contains) expr).negated());
	}

	@Test
	void testAndExpression() {
		RuleExpression expr = RuleExpressionParser.parse(
				"cert.key_algorithm == \"RSA\" and cert.key_size < 2048");
		assertInstanceOf(RuleExpression.And.class, expr);
	}

	@Test
	void testOrExpression() {
		RuleExpression expr = RuleExpressionParser.parse(
				"protocols contains \"TLSv1.0\" or protocols contains \"TLSv1.1\"");
		assertInstanceOf(RuleExpression.Or.class, expr);
	}

	@Test
	void testNotExpression() {
		RuleExpression expr = RuleExpressionParser.parse("not session.headers_available");
		assertInstanceOf(RuleExpression.Not.class, expr);
	}

	@Test
	void testCompoundAndOr() {
		// "and" binds tighter than "or"
		RuleExpression expr = RuleExpressionParser.parse(
				"a == 1 or b == 2 and c == 3");
		assertInstanceOf(RuleExpression.Or.class, expr);
		RuleExpression.Or or = (RuleExpression.Or) expr;
		assertInstanceOf(RuleExpression.Comparison.class, or.left());
		assertInstanceOf(RuleExpression.And.class, or.right());
	}

	@Test
	void testParenthesizedExpression() {
		RuleExpression expr = RuleExpressionParser.parse("(a == 1 or b == 2) and c == 3");
		assertInstanceOf(RuleExpression.And.class, expr);
		RuleExpression.And and = (RuleExpression.And) expr;
		assertInstanceOf(RuleExpression.Or.class, and.left());
	}

	@Test
	void testFunctionCallNoArgs() {
		// Not a common case, but should parse
		RuleExpression expr = RuleExpressionParser.parse("count(ciphers)");
		assertInstanceOf(RuleExpression.FunctionCall.class, expr);
		RuleExpression.FunctionCall fn = (RuleExpression.FunctionCall) expr;
		assertEquals("count", fn.name());
		assertEquals(1, fn.args().size());
	}

	@Test
	void testCountFiltered() {
		RuleExpression expr = RuleExpressionParser.parse(
				"count(ciphers, strength == \"WEAK\") >= 6");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		RuleExpression.Comparison cmp = (RuleExpression.Comparison) expr;
		assertInstanceOf(RuleExpression.CountFiltered.class, cmp.left());
		RuleExpression.CountFiltered cf = (RuleExpression.CountFiltered) cmp.left();
		assertEquals("strength", cf.filterField());
		assertEquals("==", cf.filterOp());
	}

	@Test
	void testHeaderFunction() {
		RuleExpression expr = RuleExpressionParser.parse(
				"header(\"Strict-Transport-Security\") == null");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		RuleExpression.Comparison cmp = (RuleExpression.Comparison) expr;
		assertInstanceOf(RuleExpression.FunctionCall.class, cmp.left());
	}

	@Test
	void testParseMaxAgeFunction() {
		RuleExpression expr = RuleExpressionParser.parse(
				"parse_max_age(header(\"Strict-Transport-Security\")) < 31536000");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
	}

	@Test
	void testComplexExpression() {
		// Simulates a real rule
		String input = "cert.key_algorithm == \"RSA\" and cert.key_size > 0 and cert.key_size < 2048";
		RuleExpression expr = RuleExpressionParser.parse(input);
		assertInstanceOf(RuleExpression.And.class, expr);
	}

	@Test
	void testComparisonWithBooleanEquals() {
		RuleExpression expr = RuleExpressionParser.parse("session.compression_enabled == true");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
	}

	@Test
	void testNullExpression() {
		assertThrows(IllegalArgumentException.class, () -> RuleExpressionParser.parse(null));
	}

	@Test
	void testBlankExpression() {
		assertThrows(IllegalArgumentException.class, () -> RuleExpressionParser.parse("  "));
	}

	@Test
	void testUnterminatedString() {
		assertThrows(IllegalArgumentException.class, () -> RuleExpressionParser.parse("\"unterminated"));
	}

	@Test
	void testMultipleAndExpressions() {
		RuleExpression expr = RuleExpressionParser.parse(
				"revocation.ocsp_status == \"ERROR\" and revocation.crl_status == \"ERROR\"");
		assertInstanceOf(RuleExpression.And.class, expr);
	}

	@Test
	void testTripleNestedAnd() {
		RuleExpression expr = RuleExpressionParser.parse("a == 1 and b == 2 and c == 3");
		// Left-associative: (a==1 and b==2) and c==3
		assertInstanceOf(RuleExpression.And.class, expr);
		RuleExpression.And outer = (RuleExpression.And) expr;
		assertInstanceOf(RuleExpression.And.class, outer.left());
	}

	@Test
	void testCountFilteredContains() {
		RuleExpression expr = RuleExpressionParser.parse(
				"count(ciphers, name contains \"RC4\") > 0");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		RuleExpression.Comparison cmp = (RuleExpression.Comparison) expr;
		assertInstanceOf(RuleExpression.CountFiltered.class, cmp.left());
		RuleExpression.CountFiltered cf = (RuleExpression.CountFiltered) cmp.left();
		assertEquals("name", cf.filterField());
		assertEquals("contains", cf.filterOp());
	}

	@Test
	void testCountFilteredNotContains() {
		RuleExpression expr = RuleExpressionParser.parse(
				"count(ciphers, name not contains \"RC4\") > 0");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		RuleExpression.Comparison cmp = (RuleExpression.Comparison) expr;
		RuleExpression.CountFiltered cf = (RuleExpression.CountFiltered) cmp.left();
		assertEquals("not contains", cf.filterOp());
	}

	@Test
	void testCountFilteredStartsWith() {
		RuleExpression expr = RuleExpressionParser.parse(
				"count(ciphers, name starts_with \"TLS_ECDHE\") > 0");
		assertInstanceOf(RuleExpression.Comparison.class, expr);
		RuleExpression.Comparison cmp = (RuleExpression.Comparison) expr;
		RuleExpression.CountFiltered cf = (RuleExpression.CountFiltered) cmp.left();
		assertEquals("name", cf.filterField());
		assertEquals("starts_with", cf.filterOp());
	}

	@Test
	void testContainsFunction() {
		RuleExpression expr = RuleExpressionParser.parse(
				"contains(upper(cert.signing_algorithm), \"SHA1\")");
		assertInstanceOf(RuleExpression.FunctionCall.class, expr);
		RuleExpression.FunctionCall fn = (RuleExpression.FunctionCall) expr;
		assertEquals("contains", fn.name());
		assertEquals(2, fn.args().size());
	}
}
