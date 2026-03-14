package com.mps.deepviolet.api.ai;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AiConfig} builder, defaults, and immutability.
 */
class AiConfigTest {

	@Test
	void testBuilderDefaults() {
		AiConfig config = AiConfig.builder().build();

		assertEquals(AiProvider.ANTHROPIC, config.getProvider());
		assertNull(config.getApiKey());
		assertNull(config.getModel());
		assertEquals(4096, config.getMaxTokens());
		assertEquals(0.3, config.getTemperature(), 0.001);
		assertEquals(AiAnalysisService.DEFAULT_SYSTEM_PROMPT, config.getSystemPrompt());
		assertNull(config.getEndpointUrl());
	}

	@Test
	void testBuilderCustomValues() {
		AiConfig config = AiConfig.builder()
				.provider(AiProvider.OLLAMA)
				.apiKey("test-key")
				.model("llama3.2:latest")
				.maxTokens(8192)
				.temperature(0.7)
				.systemPrompt("Custom prompt")
				.endpointUrl("http://localhost:11434")
				.build();

		assertEquals(AiProvider.OLLAMA, config.getProvider());
		assertEquals("test-key", config.getApiKey());
		assertEquals("llama3.2:latest", config.getModel());
		assertEquals(8192, config.getMaxTokens());
		assertEquals(0.7, config.getTemperature(), 0.001);
		assertEquals("Custom prompt", config.getSystemPrompt());
		assertEquals("http://localhost:11434", config.getEndpointUrl());
	}

	@Test
	void testImmutability() {
		AiConfig.Builder builder = AiConfig.builder()
				.provider(AiProvider.OPENAI)
				.apiKey("key1");

		AiConfig config1 = builder.build();

		// Modifying builder after build doesn't affect config1
		builder.apiKey("key2");
		AiConfig config2 = builder.build();

		assertEquals("key1", config1.getApiKey());
		assertEquals("key2", config2.getApiKey());
	}

	@Test
	void testAllProviders() {
		for (AiProvider provider : AiProvider.values()) {
			AiConfig config = AiConfig.builder()
					.provider(provider)
					.build();
			assertEquals(provider, config.getProvider());
		}
	}
}
