package com.mps.deepviolet.api.ai;

/**
 * Supported AI providers for TLS scan analysis.
 *
 * @author Milton Smith
 */
public enum AiProvider {
	/** Anthropic Claude API provider. */
	ANTHROPIC("Anthropic"),
	/** OpenAI ChatGPT API provider. */
	OPENAI("OpenAI"),
	/** Local Ollama API provider. */
	OLLAMA("Ollama");

	private final String displayName;

	AiProvider(String displayName) {
		this.displayName = displayName;
	}

	/**
	 * Returns the human-readable provider name.
	 *
	 * @return the display name
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Look up a provider by its display name (case-insensitive).
	 * Returns {@link #ANTHROPIC} if no match is found.
	 *
	 * @param name display name to look up
	 * @return matching provider, or ANTHROPIC as default
	 */
	public static AiProvider fromDisplayName(String name) {
		for (AiProvider p : values()) {
			if (p.displayName.equalsIgnoreCase(name)) {
				return p;
			}
		}
		return ANTHROPIC;
	}

	/**
	 * Get the default model identifiers for this provider.
	 *
	 * @return array of default model IDs
	 */
	public String[] getDefaultModels() {
		return switch (this) {
			case ANTHROPIC -> AiAnalysisService.ANTHROPIC_MODELS;
			case OPENAI -> AiAnalysisService.OPENAI_MODELS;
			case OLLAMA -> AiAnalysisService.OLLAMA_MODELS;
		};
	}
}
