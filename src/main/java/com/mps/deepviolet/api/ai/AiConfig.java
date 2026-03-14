package com.mps.deepviolet.api.ai;

/**
 * Immutable configuration for AI analysis requests.
 * Use {@link #builder()} to construct instances.
 *
 * @author Milton Smith
 */
public final class AiConfig {

	private final AiProvider provider;
	private final String apiKey;
	private final String model;
	private final int maxTokens;
	private final double temperature;
	private final String systemPrompt;
	private final String endpointUrl;

	private AiConfig(Builder builder) {
		this.provider = builder.provider;
		this.apiKey = builder.apiKey;
		this.model = builder.model;
		this.maxTokens = builder.maxTokens;
		this.temperature = builder.temperature;
		this.systemPrompt = builder.systemPrompt;
		this.endpointUrl = builder.endpointUrl;
	}

	public AiProvider getProvider() {
		return provider;
	}

	public String getApiKey() {
		return apiKey;
	}

	public String getModel() {
		return model;
	}

	public int getMaxTokens() {
		return maxTokens;
	}

	public double getTemperature() {
		return temperature;
	}

	public String getSystemPrompt() {
		return systemPrompt;
	}

	public String getEndpointUrl() {
		return endpointUrl;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private AiProvider provider = AiProvider.ANTHROPIC;
		private String apiKey;
		private String model;
		private int maxTokens = 4096;
		private double temperature = AiAnalysisService.DEFAULT_TEMPERATURE;
		private String systemPrompt = AiAnalysisService.DEFAULT_SYSTEM_PROMPT;
		private String endpointUrl;

		public Builder provider(AiProvider provider) {
			this.provider = provider;
			return this;
		}

		public Builder apiKey(String apiKey) {
			this.apiKey = apiKey;
			return this;
		}

		public Builder model(String model) {
			this.model = model;
			return this;
		}

		public Builder maxTokens(int maxTokens) {
			this.maxTokens = maxTokens;
			return this;
		}

		public Builder temperature(double temperature) {
			this.temperature = temperature;
			return this;
		}

		public Builder systemPrompt(String systemPrompt) {
			this.systemPrompt = systemPrompt;
			return this;
		}

		public Builder endpointUrl(String endpointUrl) {
			this.endpointUrl = endpointUrl;
			return this;
		}

		public AiConfig build() {
			return new AiConfig(this);
		}
	}
}
