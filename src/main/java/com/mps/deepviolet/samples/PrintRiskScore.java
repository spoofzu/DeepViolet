package com.mps.deepviolet.samples;

import java.net.URL;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.IRiskScore.IDeduction.IScope;
import com.mps.deepviolet.api.ISession;

public class PrintRiskScore {

	public PrintRiskScore() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		IRiskScore score = eng.getRiskScore();

		System.out.println("=== TLS Risk Score for " + score.getHostUrl() + " ===");
		System.out.println("Total Score: " + score.getTotalScore() + "/100");
		System.out.println("Grade:       " + score.getLetterGrade());
		System.out.println("Risk Level:  " + score.getRiskLevel());
		System.out.println();

		for (ICategoryScore cat : score.getCategoryScores()) {
			System.out.println(cat.getDisplayName() + ": " + cat.getScore() + "/100"
					+ " [" + cat.getRiskLevel() + "]");
			System.out.println("  " + cat.getSummary());
			for (IDeduction d : cat.getDeductions()) {
				String scopeTag = "";
				IScope scope = d.getScope();
				if (scope != null) {
					StringBuilder sb = new StringBuilder(" [").append(scope.getLayer());
					if (scope.getProtocols().length > 0) {
						sb.append(' ').append(String.join(",", scope.getProtocols()));
					}
					if (scope.getAspect() != null) {
						sb.append(" / ").append(scope.getAspect());
					}
					sb.append(']');
					scopeTag = sb.toString();
				}
				System.out.printf("    - %s (score=%.2f, %s)%s%s%n",
						d.getDescription(), d.getScore(), d.getSeverity(),
						d.isInconclusive() ? " [inconclusive]" : "",
						scopeTag);
			}
		}

		System.out.flush();
	}

	public static final void main(String[] args) {
		try {
			new PrintRiskScore();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
