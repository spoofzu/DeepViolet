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

	/**
	 * Returns the AI provider.
	 *
	 * @return the provider
	 */
	public AiProvider getProvider() {
		return provider;
	}

	/**
	 * Returns the API key.
	 *
	 * @return the API key, or {@code null} if not set
	 */
	public String getApiKey() {
		return apiKey;
	}

	/**
	 * Returns the model identifier.
	 *
	 * @return the model ID, or {@code null} if not set
	 */
	public String getModel() {
		return model;
	}

	/**
	 * Returns the maximum number of response tokens.
	 *
	 * @return max tokens
	 */
	public int getMaxTokens() {
		return maxTokens;
	}

	/**
	 * Returns the sampling temperature.
	 *
	 * @return temperature value
	 */
	public double getTemperature() {
		return temperature;
	}

	/**
	 * Returns the system prompt.
	 *
	 * @return the system prompt
	 */
	public String getSystemPrompt() {
		return systemPrompt;
	}

	/**
	 * Returns the provider endpoint URL (Ollama only).
	 *
	 * @return the endpoint URL, or {@code null} if not set
	 */
	public String getEndpointUrl() {
		return endpointUrl;
	}

	/**
	 * Creates a new builder with default values.
	 *
	 * @return a new builder
	 */
	public static Builder builder() {
		return new Builder();
	}

	/** Builder for constructing {@link AiConfig} instances. */
	public static class Builder {
		private AiProvider provider = AiProvider.ANTHROPIC;
		private String apiKey;
		private String model;
		private int maxTokens = 4096;
		private double temperature = AiAnalysisService.DEFAULT_TEMPERATURE;
		private String systemPrompt = AiAnalysisService.DEFAULT_SYSTEM_PROMPT;
		private String endpointUrl;

		/** Creates a builder with default values. */
		Builder() {}

		/**
		 * Sets the AI provider.
		 *
		 * @param provider the provider
		 * @return this builder
		 */
		public Builder provider(AiProvider provider) {
			this.provider = provider;
			return this;
		}

		/**
		 * Sets the API key.
		 *
		 * @param apiKey the API key
		 * @return this builder
		 */
		public Builder apiKey(String apiKey) {
			this.apiKey = apiKey;
			return this;
		}

		/**
		 * Sets the model identifier.
		 *
		 * @param model the model ID
		 * @return this builder
		 */
		public Builder model(String model) {
			this.model = model;
			return this;
		}

		/**
		 * Sets the maximum number of response tokens.
		 *
		 * @param maxTokens max tokens
		 * @return this builder
		 */
		public Builder maxTokens(int maxTokens) {
			this.maxTokens = maxTokens;
			return this;
		}

		/**
		 * Sets the sampling temperature.
		 *
		 * @param temperature temperature value
		 * @return this builder
		 */
		public Builder temperature(double temperature) {
			this.temperature = temperature;
			return this;
		}

		/**
		 * Sets the system prompt.
		 *
		 * @param systemPrompt the system prompt
		 * @return this builder
		 */
		public Builder systemPrompt(String systemPrompt) {
			this.systemPrompt = systemPrompt;
			return this;
		}

		/**
		 * Sets the provider endpoint URL (Ollama only).
		 *
		 * @param endpointUrl the endpoint URL
		 * @return this builder
		 */
		public Builder endpointUrl(String endpointUrl) {
			this.endpointUrl = endpointUrl;
			return this;
		}

		/**
		 * Builds an immutable {@link AiConfig} from this builder's state.
		 *
		 * @return the config
		 */
		public AiConfig build() {
			return new AiConfig(this);
		}
	}
}
