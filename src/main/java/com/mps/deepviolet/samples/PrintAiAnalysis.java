package com.mps.deepviolet.samples;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.ai.AiConfig;
import com.mps.deepviolet.api.ai.AiProvider;
import com.mps.deepviolet.api.ai.IAiAnalysisService;

public class PrintAiAnalysis {

	public PrintAiAnalysis() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		// Configure AI — API key from environment
		AiConfig config = AiConfig.builder()
				.provider(AiProvider.ANTHROPIC)
				.apiKey(System.getenv("DV_AI_API_KEY"))
				.model("claude-sonnet-4-5-20250929")
				.build();

		// Option 1: One-call analysis from engine state
		String analysis = eng.getAiAnalysis(config);
		System.out.println(analysis);

		// Option 2: Analyze from a saved report file
		IAiAnalysisService ai = DeepVioletFactory.getAiService();
		try (InputStream fileStream = Files.newInputStream(Path.of("saved-report.txt"))) {
			String fileAnalysis = ai.analyze(fileStream, config);
			System.out.println(fileAnalysis);
		}

		// Option 3: Analyze from an in-memory string
		String reportText = "... scan report text ...";
		try (InputStream memStream = new ByteArrayInputStream(
				reportText.getBytes(StandardCharsets.UTF_8))) {
			String memAnalysis = ai.analyze(memStream, config);
			System.out.println(memAnalysis);
		}
	}

	public static final void main(String[] args) {
		try {
			new PrintAiAnalysis();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
