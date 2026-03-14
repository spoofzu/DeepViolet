package com.mps.deepviolet.api.ai;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AiAnalysisService} in the DV API.
 * Tests provider enum, model arrays, config, and InputStream handling.
 * Network-dependent tests (actual API calls) are not included here.
 */
class AiAnalysisServiceTest {

	@Test
	void testProviderFromDisplayName() {
		assertEquals(AiProvider.ANTHROPIC, AiProvider.fromDisplayName("Anthropic"));
		assertEquals(AiProvider.OPENAI, AiProvider.fromDisplayName("OpenAI"));
		assertEquals(AiProvider.OLLAMA, AiProvider.fromDisplayName("Ollama"));
		// Case insensitive
		assertEquals(AiProvider.ANTHROPIC, AiProvider.fromDisplayName("anthropic"));
		assertEquals(AiProvider.OLLAMA, AiProvider.fromDisplayName("ollama"));
		// Unknown falls back to ANTHROPIC
		assertEquals(AiProvider.ANTHROPIC, AiProvider.fromDisplayName("unknown"));
	}

	@Test
	void testProviderDisplayNames() {
		assertEquals("Anthropic", AiProvider.ANTHROPIC.getDisplayName());
		assertEquals("OpenAI", AiProvider.OPENAI.getDisplayName());
		assertEquals("Ollama", AiProvider.OLLAMA.getDisplayName());
	}

	@Test
	void testProviderGetDefaultModels() {
		String[] anthropic = AiProvider.ANTHROPIC.getDefaultModels();
		assertNotNull(anthropic);
		assertTrue(anthropic.length > 0);
		assertEquals("claude-sonnet-4-5-20250929", anthropic[0]);

		String[] openai = AiProvider.OPENAI.getDefaultModels();
		assertNotNull(openai);
		assertTrue(openai.length > 0);
		assertEquals("gpt-4o", openai[0]);

		String[] ollama = AiProvider.OLLAMA.getDefaultModels();
		assertNotNull(ollama);
		assertTrue(ollama.length > 0);
		assertEquals("llama3.2:latest", ollama[0]);
	}

	@Test
	void testAnthropicModelArray() {
		String[] models = AiAnalysisService.ANTHROPIC_MODELS;
		assertNotNull(models);
		assertTrue(models.length > 0);
		assertEquals("claude-sonnet-4-5-20250929", models[0]);
	}

	@Test
	void testOpenAIModelArray() {
		String[] models = AiAnalysisService.OPENAI_MODELS;
		assertNotNull(models);
		assertTrue(models.length > 0);
		assertEquals("gpt-4o", models[0]);
	}

	@Test
	void testOllamaModelArray() {
		String[] models = AiAnalysisService.OLLAMA_MODELS;
		assertNotNull(models);
		assertTrue(models.length > 0);
		assertEquals("llama3.2:latest", models[0]);
	}

	@Test
	void testDefaultConstants() {
		assertEquals(0.3, AiAnalysisService.DEFAULT_TEMPERATURE, 0.001);
		assertEquals("http://localhost:11434", AiAnalysisService.DEFAULT_OLLAMA_ENDPOINT);
		assertNotNull(AiAnalysisService.DEFAULT_SYSTEM_PROMPT);
		assertFalse(AiAnalysisService.DEFAULT_SYSTEM_PROMPT.isBlank());
		assertTrue(AiAnalysisService.DEFAULT_SYSTEM_PROMPT.contains("TLS"));
		assertNotNull(AiAnalysisService.DEFAULT_CHAT_SYSTEM_PROMPT);
		assertFalse(AiAnalysisService.DEFAULT_CHAT_SYSTEM_PROMPT.isBlank());
	}

	@Test
	void testAnalyze_missingApiKey_throws() {
		AiAnalysisService service = new AiAnalysisService();
		AiConfig config = AiConfig.builder()
				.provider(AiProvider.ANTHROPIC)
				.apiKey("")
				.model("claude-sonnet-4-5-20250929")
				.build();

		InputStream stream = new ByteArrayInputStream("test report".getBytes(StandardCharsets.UTF_8));
		assertThrows(AiAnalysisException.class, () -> service.analyze(stream, config));
	}

	@Test
	void testAnalyze_nullApiKey_throws() {
		AiAnalysisService service = new AiAnalysisService();
		AiConfig config = AiConfig.builder()
				.provider(AiProvider.OPENAI)
				.apiKey(null)
				.model("gpt-4o")
				.build();

		InputStream stream = new ByteArrayInputStream("test report".getBytes(StandardCharsets.UTF_8));
		assertThrows(AiAnalysisException.class, () -> service.analyze(stream, config));
	}

	@Test
	void testAnalyze_ollama_blankKey_doesNotThrowKeyError() {
		AiAnalysisService service = new AiAnalysisService();
		AiConfig config = AiConfig.builder()
				.provider(AiProvider.OLLAMA)
				.apiKey("")
				.model("llama3.2:latest")
				.endpointUrl("http://localhost:99999")
				.build();

		InputStream stream = new ByteArrayInputStream("test report".getBytes(StandardCharsets.UTF_8));
		AiAnalysisException ex = assertThrows(AiAnalysisException.class,
				() -> service.analyze(stream, config));
		assertFalse(ex.getMessage().contains("API key is required"),
				"Ollama should not require an API key");
	}

	@Test
	void testFetchModels_delegates() {
		AiAnalysisService service = new AiAnalysisService();

		// Without a real API key, fetchModels returns defaults
		String[] anthropic = service.fetchModels(AiProvider.ANTHROPIC, null, null);
		assertArrayEquals(AiAnalysisService.ANTHROPIC_MODELS, anthropic);

		String[] openai = service.fetchModels(AiProvider.OPENAI, "", null);
		assertArrayEquals(AiAnalysisService.OPENAI_MODELS, openai);
	}

	@Test
	void testChatMessage_record() {
		AiChatMessage msg = new AiChatMessage("user", "hello");
		assertEquals("user", msg.role());
		assertEquals("hello", msg.content());
	}
}
