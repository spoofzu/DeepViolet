package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;

import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.api.IRiskScore.IDeduction;
import com.mps.deepviolet.api.IRiskScore.ScoreCategory;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Integration test that computes a risk score against a live host.
 * Disabled by default -- requires network connectivity.
 */
@Disabled("Requires live network connection")
public class RiskScoreIntegrationTest {

	@Test
	public void testRiskScoreAgainstLiveHost() throws Exception {
		URL url = new URL("https://www.google.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		IRiskScore score = eng.getRiskScore();

		assertNotNull(score);
		assertTrue(score.getTotalScore() >= 0 && score.getTotalScore() <= 100,
				"Score should be 0-100, was: " + score.getTotalScore());
		assertNotNull(score.getLetterGrade());
		assertNotNull(score.getRiskLevel());
		assertNotNull(score.getHostUrl());

		ICategoryScore[] categories = score.getCategoryScores();
		assertEquals(6, categories.length);

		for (ScoreCategory cat : ScoreCategory.values()) {
			ICategoryScore catScore = score.getCategoryScore(cat);
			assertNotNull(catScore, "Missing category: " + cat);
			assertTrue(catScore.getScore() >= 0);
			assertTrue(catScore.getScore() <= 100);
			assertNotNull(catScore.getDisplayName());
			assertNotNull(catScore.getSummary());
			assertNotNull(catScore.getDeductions());
		}

		// Print results
		System.out.println("=== Risk Score for " + score.getHostUrl() + " ===");
		System.out.println("Total: " + score.getTotalScore() + "/100");
		System.out.println("Grade: " + score.getLetterGrade());
		System.out.println("Risk:  " + score.getRiskLevel());
		System.out.println();
		for (ICategoryScore cat : categories) {
			System.out.println(cat.getDisplayName() + ": " + cat.getScore() + "/100"
					+ " [" + cat.getRiskLevel() + "]");
			System.out.println("  " + cat.getSummary());
			for (IDeduction d : cat.getDeductions()) {
				System.out.printf("  - %s (score=%.2f, %s)%n",
						d.getDescription(), d.getScore(), d.getSeverity());
			}
		}
	}
}
