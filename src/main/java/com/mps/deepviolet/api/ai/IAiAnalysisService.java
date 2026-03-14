package com.mps.deepviolet.api.ai;

import java.io.InputStream;
import java.util.List;

/**
 * Service interface for AI-powered analysis of TLS scan reports.
 * Supports report analysis, multi-turn chat, and model discovery.
 *
 * @author Milton Smith
 */
public interface IAiAnalysisService {

	/**
	 * Analyze a TLS scan report using an AI provider.
	 * The caller provides scan data as an InputStream, leaving the
	 * source open (file, URL, ByteArrayInputStream from a String, etc.).
	 *
	 * @param scanReport  InputStream providing the plain text scan report
	 * @param config      AI configuration (provider, model, key, etc.)
	 * @return AI analysis text
	 * @throws AiAnalysisException on any error
	 */
	String analyze(InputStream scanReport, AiConfig config) throws AiAnalysisException;

	/**
	 * Multi-turn chat about TLS scan results.
	 *
	 * @param messages    conversation history
	 * @param config      AI configuration
	 * @return AI response text
	 * @throws AiAnalysisException on any error
	 */
	String chat(List<AiChatMessage> messages, AiConfig config) throws AiAnalysisException;

	/**
	 * Fetch available models for the given provider.
	 *
	 * @param provider    AI provider
	 * @param apiKey      API key (null for Ollama)
	 * @param endpointUrl endpoint URL (Ollama only)
	 * @return array of model identifiers
	 */
	String[] fetchModels(AiProvider provider, String apiKey, String endpointUrl);
}
