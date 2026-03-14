package com.mps.deepviolet.persist;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * JSON serialization/deserialization for {@link ScanSnapshot}.
 * Package-private — accessed only through {@link ScanFileIO}.
 *
 * @author Milton Smith
 */
class ScanJsonCodec {

	private static final Gson PRETTY_GSON = new GsonBuilder()
			.setPrettyPrinting().create();
	private static final Gson GSON = new Gson();

	String encode(ScanSnapshot snapshot) {
		Map<String, Object> jsonMap = new LinkedHashMap<>();
		jsonMap.put("report_type", "scan");
		jsonMap.put("total_targets", snapshot.getTotalTargets());
		jsonMap.put("success_count", snapshot.getSuccessCount());
		jsonMap.put("error_count", snapshot.getErrorCount());

		if (snapshot.getScanId() != null) {
			jsonMap.put("scan_id", snapshot.getScanId());
		}

		List<Map<String, Object>> hosts = new ArrayList<>();
		for (HostSnapshot hs : snapshot.getHosts()) {
			Map<String, Object> hostMap = new LinkedHashMap<>();
			hostMap.put("target_url", hs.getTargetUrl());
			hostMap.put("success", hs.isSuccess());
			if (hs.getErrorMessage() != null) {
				hostMap.put("error", hs.getErrorMessage());
			}
			if (hs.getSecurityHeaders() != null) {
				hostMap.put("security_headers", hs.getSecurityHeaders());
			}
			if (hs.getConnProperties() != null) {
				hostMap.put("connection_properties", hs.getConnProperties());
			}
			if (hs.getHttpHeaders() != null) {
				hostMap.put("http_headers", hs.getHttpHeaders());
			}
			if (hs.getTlsFingerprint() != null) {
				hostMap.put("tls_fingerprint", hs.getTlsFingerprint());
			}
			if (hs.getRiskScore() != null) {
				hostMap.put("risk_score", encodeRiskScore(hs.getRiskScore()));
			}
			if (hs.getCiphers() != null) {
				List<Map<String, String>> cipherList = new ArrayList<>();
				for (ICipherSuite cs : hs.getCiphers()) {
					Map<String, String> c = new LinkedHashMap<>();
					c.put("name", cs.getSuiteName());
					c.put("strength", cs.getStrengthEvaluation());
					c.put("protocol", cs.getHandshakeProtocol());
					cipherList.add(c);
				}
				hostMap.put("ciphers", cipherList);
			}
			if (hs.getReportTree() != null) {
				hostMap.put("scan_report", hs.getReportTree());
			}
			if (hs.getRuleContextMap() != null) {
				hostMap.put("rule_context", hs.getRuleContextMap());
			}
			hosts.add(hostMap);
		}
		jsonMap.put("hosts", hosts);

		return PRETTY_GSON.toJson(jsonMap);
	}

	@SuppressWarnings("unchecked")
	ScanSnapshot decode(Map<String, Object> jsonMap) {
		ScanSnapshot snapshot = new ScanSnapshot();
		snapshot.setTotalTargets(toInt(jsonMap.get("total_targets")));
		snapshot.setSuccessCount(toInt(jsonMap.get("success_count")));
		snapshot.setErrorCount(toInt(jsonMap.get("error_count")));

		// ignore "target_source" from old files — backward compat
		String scanId = (String) jsonMap.get("scan_id");
		if (scanId != null) {
			snapshot.setScanId(scanId);
		}

		List<Map<String, Object>> hosts =
				(List<Map<String, Object>>) jsonMap.get("hosts");
		if (hosts != null) {
			for (Map<String, Object> hostMap : hosts) {
				String targetUrl = (String) hostMap.get("target_url");
				HostSnapshot hs = new HostSnapshot(targetUrl);

				Boolean success = (Boolean) hostMap.get("success");
				if (success != null && !success) {
					hs.setErrorMessage((String) hostMap.get("error"));
				}

				Map<String, String> secHeaders = toStringMap(
						hostMap.get("security_headers"));
				if (secHeaders != null) hs.setSecurityHeaders(secHeaders);

				Map<String, String> connProps = toStringMap(
						hostMap.get("connection_properties"));
				if (connProps != null) hs.setConnProperties(connProps);

				Map<String, String> httpHeaders = toStringMap(
						hostMap.get("http_headers"));
				if (httpHeaders != null) hs.setHttpHeaders(httpHeaders);

				if (hostMap.get("tls_fingerprint") != null) {
					hs.setTlsFingerprint(String.valueOf(
							hostMap.get("tls_fingerprint")));
				}

				Map<String, Object> riskMap =
						(Map<String, Object>) hostMap.get("risk_score");
				if (riskMap != null) {
					hs.setRiskScore(decodeRiskScore(riskMap));
				}

				List<Map<String, String>> cipherList =
						(List<Map<String, String>>) hostMap.get("ciphers");
				if (cipherList != null) {
					ICipherSuite[] ciphers = new ICipherSuite[cipherList.size()];
					for (int i = 0; i < cipherList.size(); i++) {
						Map<String, String> c = cipherList.get(i);
						ciphers[i] = new ImmutableCipherSuite(
								c.get("name"), c.get("strength"),
								c.get("protocol"));
					}
					hs.setCiphers(ciphers);
				}

				Map<String, Object> scanReport =
						(Map<String, Object>) hostMap.get("scan_report");
				if (scanReport != null) {
					hs.setReportTree(scanReport);
				}

				Map<String, Object> ruleCtxMap =
						(Map<String, Object>) hostMap.get("rule_context");
				if (ruleCtxMap != null) {
					hs.setRuleContextMap(ruleCtxMap);
				}

				snapshot.addHost(hs);
			}
		}
		return snapshot;
	}

	// ---- Helpers ----

	private Map<String, Object> encodeRiskScore(IRiskScore rs) {
		Map<String, Object> risk = new LinkedHashMap<>();
		risk.put("total_score", rs.getTotalScore());
		risk.put("letter_grade", rs.getLetterGrade().name());
		risk.put("risk_level", rs.getRiskLevel().name());

		IRiskScore.ICategoryScore[] catScores = rs.getCategoryScores();
		if (catScores != null && catScores.length > 0) {
			List<Map<String, Object>> categories = new ArrayList<>();
			for (IRiskScore.ICategoryScore cs : catScores) {
				Map<String, Object> catMap = new LinkedHashMap<>();
				catMap.put("category_key", cs.getCategoryKey());
				catMap.put("display_name", cs.getDisplayName());
				catMap.put("score", cs.getScore());
				catMap.put("risk_level", cs.getRiskLevel().name());
				catMap.put("summary", cs.getSummary());

				IRiskScore.IDeduction[] deds = cs.getDeductions();
				if (deds != null && deds.length > 0) {
					List<Map<String, Object>> dedList = new ArrayList<>();
					for (IRiskScore.IDeduction d : deds) {
						Map<String, Object> dedMap = new LinkedHashMap<>();
						dedMap.put("rule_id", d.getRuleId());
						dedMap.put("description", d.getDescription());
						dedMap.put("score", d.getScore());
						dedMap.put("severity", d.getSeverity());
						dedMap.put("inconclusive", d.isInconclusive());
						dedList.add(dedMap);
					}
					catMap.put("deductions", dedList);
				}
				categories.add(catMap);
			}
			risk.put("categories", categories);
		}
		return risk;
	}

	@SuppressWarnings("unchecked")
	private IRiskScore decodeRiskScore(Map<String, Object> riskMap) {
		IRiskScore.ICategoryScore[] catScores =
				parseCategoryScores(riskMap.get("categories"));
		return new ImmutableRiskScore(
				toInt(riskMap.get("total_score")),
				IRiskScore.LetterGrade.valueOf(
						(String) riskMap.get("letter_grade")),
				IRiskScore.RiskLevel.valueOf(
						(String) riskMap.get("risk_level")),
				catScores);
	}

	@SuppressWarnings("unchecked")
	private IRiskScore.ICategoryScore[] parseCategoryScores(Object obj) {
		if (obj == null) return new IRiskScore.ICategoryScore[0];
		List<Map<String, Object>> catList = (List<Map<String, Object>>) obj;
		IRiskScore.ICategoryScore[] result =
				new IRiskScore.ICategoryScore[catList.size()];
		for (int i = 0; i < catList.size(); i++) {
			Map<String, Object> catMap = catList.get(i);
			IRiskScore.IDeduction[] deductions =
					parseDeductions(catMap.get("deductions"));
			result[i] = new ImmutableCategoryScore(
					(String) catMap.get("category_key"),
					(String) catMap.get("display_name"),
					toInt(catMap.get("score")),
					IRiskScore.RiskLevel.valueOf(
							(String) catMap.get("risk_level")),
					(String) catMap.get("summary"),
					deductions);
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private IRiskScore.IDeduction[] parseDeductions(Object obj) {
		if (obj == null) return new IRiskScore.IDeduction[0];
		List<Map<String, Object>> dedList = (List<Map<String, Object>>) obj;
		IRiskScore.IDeduction[] result = new IRiskScore.IDeduction[dedList.size()];
		for (int i = 0; i < dedList.size(); i++) {
			Map<String, Object> d = dedList.get(i);
			result[i] = new ImmutableDeduction(
					(String) d.get("rule_id"),
					(String) d.get("description"),
					toDouble(d.get("score")),
					(String) d.get("severity"),
					Boolean.TRUE.equals(d.get("inconclusive")));
		}
		return result;
	}

	private static int toInt(Object obj) {
		if (obj instanceof Number) return ((Number) obj).intValue();
		if (obj instanceof String) return Integer.parseInt((String) obj);
		return 0;
	}

	private static double toDouble(Object obj) {
		if (obj instanceof Number) return ((Number) obj).doubleValue();
		if (obj instanceof String) return Double.parseDouble((String) obj);
		return 0.0;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, String> toStringMap(Object obj) {
		if (obj == null) return null;
		Map<String, Object> raw = (Map<String, Object>) obj;
		Map<String, String> result = new LinkedHashMap<>();
		for (Map.Entry<String, Object> e : raw.entrySet()) {
			result.put(e.getKey(), e.getValue() != null
					? String.valueOf(e.getValue()) : null);
		}
		return result;
	}
}
