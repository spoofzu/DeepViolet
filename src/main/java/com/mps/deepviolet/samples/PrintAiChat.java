package com.mps.deepviolet.samples;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.ai.*;

public class PrintAiChat {

	public PrintAiChat() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		AiConfig config = AiConfig.builder()
				.provider(AiProvider.OLLAMA)
				.model("llama3.2:latest")
				.systemPrompt(AiAnalysisService.DEFAULT_CHAT_SYSTEM_PROMPT)
				.build();

		IAiAnalysisService ai = DeepVioletFactory.getAiService();

		// Get engine-generated analysis as chat context
		String scanReport = eng.getAiAnalysis(config);

		// Multi-turn chat
		List<AiChatMessage> history = new ArrayList<>();
		history.add(new AiChatMessage("user",
				"Here is a TLS scan report:\n" + scanReport +
				"\n\nWhat is the biggest risk?"));

		String response = ai.chat(history, config);
		System.out.println("AI: " + response);

		// Follow-up
		history.add(new AiChatMessage("assistant", response));
		history.add(new AiChatMessage("user", "How do I fix it?"));

		response = ai.chat(history, config);
		System.out.println("AI: " + response);
	}

	public static final void main(String[] args) {
		try {
			new PrintAiChat();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
