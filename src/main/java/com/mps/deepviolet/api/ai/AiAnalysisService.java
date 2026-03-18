package com.mps.deepviolet.api.ai;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for Anthropic, OpenAI, and Ollama AI provider APIs.
 * Uses {@code java.net.http.HttpClient} (Java 21+) and Gson for JSON.
 * <p>
 * This class implements {@link IAiAnalysisService} and accepts
 * {@link InputStream}-based scan report input and {@link AiConfig}
 * for configuration.
 *
 * @author Milton Smith
 */
public class AiAnalysisService implements IAiAnalysisService {

	/** Creates a new AI analysis service instance. */
	public AiAnalysisService() {}

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolet.api.ai.AiAnalysisService");

	private static final Logger aiReportLog = LoggerFactory
			.getLogger("ai-inline");

	private static final Logger aiChatLog = LoggerFactory
			.getLogger("ai-chat");

	private static final HttpClient httpClient = HttpClient.newBuilder()
			.connectTimeout(Duration.ofSeconds(30))
			.build();

	/** Default Anthropic model identifiers. */
	public static final String[] ANTHROPIC_MODELS = {
		"claude-sonnet-4-5-20250929", "claude-haiku-4-5-20251001"
	};

	/** Default OpenAI model identifiers. */
	public static final String[] OPENAI_MODELS = {
		"gpt-4o", "gpt-4o-mini"
	};

	/** Default Ollama model identifiers. */
	public static final String[] OLLAMA_MODELS = {
		"llama3.2:latest", "mistral:latest", "gemma2:latest"
	};

	/** Default Ollama API endpoint URL. */
	public static final String DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434";

	/** Default sampling temperature for AI requests. */
	public static final double DEFAULT_TEMPERATURE = 0.3;

	/** Default system prompt for single-shot scan analysis. */
	public static final String DEFAULT_SYSTEM_PROMPT = """
			You are a TLS/SSL security expert analyzing a DeepViolet scan report. \
			The risk assessment lists findings identified by stable rule IDs \
			(e.g., "DV-R0000012 [HIGH] Strict-Transport-Security header missing \
			(-6 pts)"). Your job is to explain each finding so the reader \
			understands the technology involved, why it matters, and how to fix it.

			Respond using EXACTLY the section format below. Each section starts \
			with its name in square brackets on its own line. Write plain text \
			only — no markdown, no bullet characters (*, -, #), no bold/italic \
			markers (**).

			[Executive Summary]
			Write 2-4 sentences assessing the overall TLS security posture. \
			Reference the overall score, grade, and risk level. Identify the \
			single most impactful finding by its rule ID.

			Next, for EACH finding listed in the risk assessment, \
			write a section using exactly this format:

			[RULE-ID [SEVERITY] Brief description from the finding]
			What it is: One or two sentences explaining what the technology, \
			standard, or configuration does in plain language.
			Why it matters: One or two sentences explaining the security impact \
			of this specific finding — what attack or weakness it enables.
			Remediation: One sentence with a specific, actionable fix.

			After all item sections, include these two sections:

			[Positive Findings]
			One finding per line, prefixed with "OK: ". Note security measures \
			properly configured. Reference specific values from the scan.

			[Recommendations]
			Numbered list (1. 2. 3. ...) of prioritized action items. Reference \
			rule IDs where applicable. Each is one sentence. Limit to 5-8.

			Rules:
			- Address every finding from the risk assessment, not just critical ones.
			- Do not repeat the finding verbatim — add explanatory value.
			- Reference specific protocols, ciphers, scores, or certificates.
			- Keep each item analysis to 3-4 lines (What/Why/Remediation).
			- Keep the entire response under 1200 words.
			- Do not add sections beyond those defined above.""";

	/** Default system prompt for multi-turn chat conversations. */
	public static final String DEFAULT_CHAT_SYSTEM_PROMPT = """
			You answer TLS/SSL questions about DeepViolet scan results. \
			HARD LIMIT: 5 sentences maximum. Never exceed 5 sentences. \
			Everything past the fifth sentence is silently discarded \
			and the user never sees it. Put your most important point \
			first. No markdown, no bold, no bullet lists, no numbered \
			lists, no headings, no line breaks. Plain sentences only.""";

	private static final Gson gson = new Gson();

	@Override
	public String analyze(InputStream scanReport, AiConfig config) throws AiAnalysisException {
		String reportText;
		try {
			reportText = new String(scanReport.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new AiAnalysisException("Failed to read scan report stream: " + e.getMessage(), e);
		}

		AiProvider provider = config.getProvider();
		if (provider != AiProvider.OLLAMA && (config.getApiKey() == null || config.getApiKey().isBlank())) {
			throw new AiAnalysisException("API key is required for AI analysis");
		}

		aiReportLog.info("AI inline report request: provider={}, model={}, maxTokens={}, temperature={}, reportLength={} chars",
				provider.getDisplayName(), config.getModel(), config.getMaxTokens(),
				config.getTemperature(), reportText.length());
		aiReportLog.debug("AI inline report full request body:\n--- SYSTEM PROMPT ---\n{}\n--- SCAN REPORT ---\n{}",
				config.getSystemPrompt(), reportText);

		long startTime = System.currentTimeMillis();
		String result;
		try {
			result = switch (provider) {
				case ANTHROPIC -> callAnthropic(reportText, config.getApiKey(), config.getModel(),
						config.getMaxTokens(), config.getTemperature(), config.getSystemPrompt());
				case OPENAI -> callOpenAI(reportText, config.getApiKey(), config.getModel(),
						config.getMaxTokens(), config.getTemperature(), config.getSystemPrompt());
				case OLLAMA -> callOllama(reportText, config.getModel(), config.getMaxTokens(),
						config.getTemperature(), config.getSystemPrompt(), config.getEndpointUrl());
			};
		} catch (AiAnalysisException e) {
			long elapsed = System.currentTimeMillis() - startTime;
			aiReportLog.info("AI inline report failed after {}ms: {}", elapsed, e.getMessage());
			throw e;
		}

		long elapsed = System.currentTimeMillis() - startTime;
		aiReportLog.info("AI inline report response: provider={}, model={}, elapsed={}ms, responseLength={} chars",
				provider.getDisplayName(), config.getModel(), elapsed, result == null ? 0 : result.length());
		aiReportLog.debug("AI inline report full response:\n{}", result);

		return result;
	}

	@Override
	public String chat(List<AiChatMessage> messages, AiConfig config) throws AiAnalysisException {
		AiProvider provider = config.getProvider();
		if (provider != AiProvider.OLLAMA && (config.getApiKey() == null || config.getApiKey().isBlank())) {
			throw new AiAnalysisException("API key is required for AI chat");
		}

		aiChatLog.info("AI chat request: provider={}, model={}, messageCount={}",
				provider.getDisplayName(), config.getModel(), messages.size());

		long startTime = System.currentTimeMillis();
		String result;
		try {
			result = switch (provider) {
				case ANTHROPIC -> callAnthropicChat(messages, config.getApiKey(), config.getModel(),
						config.getMaxTokens(), config.getTemperature(), config.getSystemPrompt());
				case OPENAI -> callOpenAIChat(messages, config.getApiKey(), config.getModel(),
						config.getMaxTokens(), config.getTemperature(), config.getSystemPrompt());
				case OLLAMA -> callOllamaChat(messages, config.getModel(), config.getMaxTokens(),
						config.getTemperature(), config.getSystemPrompt(), config.getEndpointUrl());
			};
		} catch (AiAnalysisException e) {
			long elapsed = System.currentTimeMillis() - startTime;
			aiChatLog.info("AI chat failed after {}ms: {}", elapsed, e.getMessage());
			throw e;
		}

		long elapsed = System.currentTimeMillis() - startTime;
		aiChatLog.info("AI chat response: provider={}, model={}, elapsed={}ms, responseLength={} chars",
				provider.getDisplayName(), config.getModel(), elapsed, result == null ? 0 : result.length());
		aiChatLog.debug("AI chat full response:\n{}", result);

		return result;
	}

	@Override
	public String[] fetchModels(AiProvider provider, String apiKey, String endpointUrl) {
		return switch (provider) {
			case ANTHROPIC -> fetchAnthropicModels(apiKey);
			case OPENAI -> fetchOpenAIModels(apiKey);
			case OLLAMA -> fetchOllamaModels(endpointUrl);
		};
	}

	/**
	 * Fetch available models from an Ollama instance via GET /api/tags.
	 * Falls back to {@link #OLLAMA_MODELS} on failure.
	 *
	 * @param endpointUrl Ollama base URL (e.g. "http://localhost:11434")
	 * @return array of model names
	 */
	public static String[] fetchOllamaModels(String endpointUrl) {
		if (endpointUrl == null || endpointUrl.isBlank()) {
			endpointUrl = DEFAULT_OLLAMA_ENDPOINT;
		}
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(endpointUrl.replaceAll("/+$", "") + "/api/tags"))
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
				if (root.has("models") && root.get("models").isJsonArray()) {
					JsonArray models = root.getAsJsonArray("models");
					java.util.List<String> names = new java.util.ArrayList<>();
					for (JsonElement model : models) {
						JsonObject obj = model.getAsJsonObject();
						String name = obj.has("name") ? obj.get("name").getAsString() : "";
						if (!name.isEmpty()) {
							names.add(name);
						}
					}
					if (!names.isEmpty()) {
						return names.toArray(new String[0]);
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to fetch Ollama models, using defaults", e);
		}
		return OLLAMA_MODELS;
	}

	/**
	 * Fetch available models from the Anthropic API via GET /v1/models.
	 * Falls back to {@link #ANTHROPIC_MODELS} on failure.
	 *
	 * @param apiKey Anthropic API key
	 * @return array of model IDs
	 */
	public static String[] fetchAnthropicModels(String apiKey) {
		if (apiKey == null || apiKey.isBlank()) {
			return ANTHROPIC_MODELS;
		}
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.anthropic.com/v1/models"))
					.header("x-api-key", apiKey)
					.header("anthropic-version", "2023-06-01")
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
				if (root.has("data") && root.get("data").isJsonArray()) {
					JsonArray data = root.getAsJsonArray("data");
					java.util.List<String> ids = new java.util.ArrayList<>();
					for (JsonElement model : data) {
						JsonObject obj = model.getAsJsonObject();
						String id = obj.has("id") ? obj.get("id").getAsString() : "";
						if (!id.isEmpty()) {
							ids.add(id);
						}
					}
					if (!ids.isEmpty()) {
						java.util.Collections.sort(ids);
						return ids.toArray(new String[0]);
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to fetch Anthropic models, using defaults", e);
		}
		return ANTHROPIC_MODELS;
	}

	/**
	 * Fetch available chat models from the OpenAI API via GET /v1/models.
	 * Filters to chat-capable models (gpt-*, o1*, o3*, o4-mini*, chatgpt-*).
	 * Falls back to {@link #OPENAI_MODELS} on failure.
	 *
	 * @param apiKey OpenAI API key
	 * @return array of model IDs
	 */
	public static String[] fetchOpenAIModels(String apiKey) {
		if (apiKey == null || apiKey.isBlank()) {
			return OPENAI_MODELS;
		}
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.openai.com/v1/models"))
					.header("Authorization", "Bearer " + apiKey)
					.timeout(Duration.ofSeconds(10))
					.GET()
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			if (response.statusCode() == 200) {
				JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
				if (root.has("data") && root.get("data").isJsonArray()) {
					JsonArray data = root.getAsJsonArray("data");
					java.util.List<String> ids = new java.util.ArrayList<>();
					for (JsonElement model : data) {
						JsonObject obj = model.getAsJsonObject();
						String id = obj.has("id") ? obj.get("id").getAsString() : "";
						if (!id.isEmpty() && isChatModel(id)) {
							ids.add(id);
						}
					}
					if (!ids.isEmpty()) {
						java.util.Collections.sort(ids);
						return ids.toArray(new String[0]);
					}
				}
			}
		} catch (Exception e) {
			logger.debug("Failed to fetch OpenAI models, using defaults", e);
		}
		return OPENAI_MODELS;
	}

	private static boolean isChatModel(String id) {
		return id.startsWith("gpt-") || id.startsWith("o1") || id.startsWith("o3")
				|| id.startsWith("o4-mini") || id.startsWith("chatgpt-");
	}

	// ---- Provider-specific HTTP methods ----

	private String callAnthropic(String scanReport, String apiKey, String model,
								  int maxTokens, double temperature,
								  String systemPrompt) throws AiAnalysisException {
		try {
			JsonObject body = new JsonObject();
			body.addProperty("model", model);
			body.addProperty("max_tokens", maxTokens);
			body.addProperty("temperature", temperature);
			body.addProperty("system", systemPrompt);

			JsonArray messages = new JsonArray();
			JsonObject userMsg = new JsonObject();
			userMsg.addProperty("role", "user");
			userMsg.addProperty("content", scanReport);
			messages.add(userMsg);
			body.add("messages", messages);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.anthropic.com/v1/messages"))
					.header("Content-Type", "application/json")
					.header("x-api-key", apiKey)
					.header("anthropic-version", "2023-06-01")
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleAnthropicResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("Anthropic API call failed", e);
			throw new AiAnalysisException("Anthropic API call failed: " + e.getMessage());
		}
	}

	private String handleAnthropicResponse(HttpResponse<String> response) throws AiAnalysisException {
		int status = response.statusCode();

		if (status == 401) {
			throw new AiAnalysisException("Invalid API key for Anthropic");
		} else if (status == 429) {
			throw new AiAnalysisException("Rate limit exceeded for Anthropic API");
		} else if (status >= 500) {
			throw new AiAnalysisException("Anthropic server error (HTTP " + status + ")");
		} else if (status != 200) {
			throw new AiAnalysisException("Anthropic API error (HTTP " + status + "): " + response.body());
		}

		try {
			JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
			if (root.has("content") && root.get("content").isJsonArray()) {
				JsonArray content = root.getAsJsonArray("content");
				if (!content.isEmpty()) {
					JsonObject first = content.get(0).getAsJsonObject();
					return first.has("text") ? first.get("text").getAsString() : "";
				}
			}
			throw new AiAnalysisException("Unexpected Anthropic response format");
		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			throw new AiAnalysisException("Failed to parse Anthropic response: " + e.getMessage());
		}
	}

	private String callOpenAI(String scanReport, String apiKey, String model,
							   int maxTokens, double temperature,
							   String systemPrompt) throws AiAnalysisException {
		try {
			JsonObject body = new JsonObject();
			body.addProperty("model", model);
			body.addProperty("max_tokens", maxTokens);
			body.addProperty("temperature", temperature);

			JsonArray messages = new JsonArray();
			JsonObject sysMsg = new JsonObject();
			sysMsg.addProperty("role", "system");
			sysMsg.addProperty("content", systemPrompt);
			messages.add(sysMsg);
			JsonObject userMsg = new JsonObject();
			userMsg.addProperty("role", "user");
			userMsg.addProperty("content", scanReport);
			messages.add(userMsg);
			body.add("messages", messages);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.openai.com/v1/chat/completions"))
					.header("Content-Type", "application/json")
					.header("Authorization", "Bearer " + apiKey)
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOpenAIResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("OpenAI API call failed", e);
			throw new AiAnalysisException("OpenAI API call failed: " + e.getMessage());
		}
	}

	private String handleOpenAIResponse(HttpResponse<String> response) throws AiAnalysisException {
		int status = response.statusCode();

		if (status == 401) {
			throw new AiAnalysisException("Invalid API key for OpenAI");
		} else if (status == 429) {
			throw new AiAnalysisException("Rate limit exceeded for OpenAI API");
		} else if (status >= 500) {
			throw new AiAnalysisException("OpenAI server error (HTTP " + status + ")");
		} else if (status != 200) {
			throw new AiAnalysisException("OpenAI API error (HTTP " + status + "): " + response.body());
		}

		try {
			JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
			if (root.has("choices") && root.get("choices").isJsonArray()) {
				JsonArray choices = root.getAsJsonArray("choices");
				if (!choices.isEmpty()) {
					JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
					return message != null && message.has("content") ? message.get("content").getAsString() : "";
				}
			}
			throw new AiAnalysisException("Unexpected OpenAI response format");
		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			throw new AiAnalysisException("Failed to parse OpenAI response: " + e.getMessage());
		}
	}

	private String callOllama(String scanReport, String model,
							   int maxTokens, double temperature,
							   String systemPrompt, String endpointUrl) throws AiAnalysisException {
		try {
			String baseUrl = (endpointUrl != null && !endpointUrl.isBlank())
					? endpointUrl : DEFAULT_OLLAMA_ENDPOINT;

			JsonObject body = new JsonObject();
			body.addProperty("model", model);
			body.addProperty("stream", false);

			JsonObject options = new JsonObject();
			options.addProperty("temperature", temperature);
			options.addProperty("num_predict", maxTokens);
			body.add("options", options);

			JsonArray messages = new JsonArray();
			JsonObject sysMsg = new JsonObject();
			sysMsg.addProperty("role", "system");
			sysMsg.addProperty("content", systemPrompt);
			messages.add(sysMsg);
			JsonObject userMsg = new JsonObject();
			userMsg.addProperty("role", "user");
			userMsg.addProperty("content", scanReport);
			messages.add(userMsg);
			body.add("messages", messages);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl.replaceAll("/+$", "") + "/api/chat"))
					.header("Content-Type", "application/json")
					.timeout(Duration.ofSeconds(300))
					.POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOllamaResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.debug("Ollama API call failed", e);
			throw new AiAnalysisException("Ollama API call failed: " + e.getMessage());
		}
	}

	private String callAnthropicChat(List<AiChatMessage> messages, String apiKey,
									  String model, int maxTokens, double temperature,
									  String systemPrompt) throws AiAnalysisException {
		try {
			JsonObject body = new JsonObject();
			body.addProperty("model", model);
			body.addProperty("max_tokens", maxTokens);
			body.addProperty("temperature", temperature);
			body.addProperty("system", systemPrompt);

			JsonArray msgArray = new JsonArray();
			for (AiChatMessage msg : messages) {
				JsonObject m = new JsonObject();
				m.addProperty("role", msg.role());
				m.addProperty("content", msg.content());
				msgArray.add(m);
			}
			body.add("messages", msgArray);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.anthropic.com/v1/messages"))
					.header("Content-Type", "application/json")
					.header("x-api-key", apiKey)
					.header("anthropic-version", "2023-06-01")
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleAnthropicResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("Anthropic chat API call failed", e);
			throw new AiAnalysisException("Anthropic API call failed: " + e.getMessage());
		}
	}

	private String callOpenAIChat(List<AiChatMessage> messages, String apiKey,
								   String model, int maxTokens, double temperature,
								   String systemPrompt) throws AiAnalysisException {
		try {
			JsonObject body = new JsonObject();
			body.addProperty("model", model);
			body.addProperty("max_tokens", maxTokens);
			body.addProperty("temperature", temperature);

			JsonArray msgArray = new JsonArray();
			JsonObject sysMsg = new JsonObject();
			sysMsg.addProperty("role", "system");
			sysMsg.addProperty("content", systemPrompt);
			msgArray.add(sysMsg);
			for (AiChatMessage msg : messages) {
				JsonObject m = new JsonObject();
				m.addProperty("role", msg.role());
				m.addProperty("content", msg.content());
				msgArray.add(m);
			}
			body.add("messages", msgArray);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create("https://api.openai.com/v1/chat/completions"))
					.header("Content-Type", "application/json")
					.header("Authorization", "Bearer " + apiKey)
					.timeout(Duration.ofSeconds(120))
					.POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOpenAIResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.error("OpenAI chat API call failed", e);
			throw new AiAnalysisException("OpenAI API call failed: " + e.getMessage());
		}
	}

	private String callOllamaChat(List<AiChatMessage> messages, String model,
								   int maxTokens, double temperature,
								   String systemPrompt, String endpointUrl) throws AiAnalysisException {
		try {
			String baseUrl = (endpointUrl != null && !endpointUrl.isBlank())
					? endpointUrl : DEFAULT_OLLAMA_ENDPOINT;

			JsonObject body = new JsonObject();
			body.addProperty("model", model);
			body.addProperty("stream", false);

			JsonObject options = new JsonObject();
			options.addProperty("temperature", temperature);
			options.addProperty("num_predict", maxTokens);
			body.add("options", options);

			JsonArray msgArray = new JsonArray();
			JsonObject sysMsg = new JsonObject();
			sysMsg.addProperty("role", "system");
			sysMsg.addProperty("content", systemPrompt);
			msgArray.add(sysMsg);
			for (AiChatMessage msg : messages) {
				JsonObject m = new JsonObject();
				m.addProperty("role", msg.role());
				m.addProperty("content", msg.content());
				msgArray.add(m);
			}
			body.add("messages", msgArray);

			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(baseUrl.replaceAll("/+$", "") + "/api/chat"))
					.header("Content-Type", "application/json")
					.timeout(Duration.ofSeconds(300))
					.POST(HttpRequest.BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<String> response = httpClient.send(request,
					HttpResponse.BodyHandlers.ofString());

			return handleOllamaResponse(response);

		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			logger.debug("Ollama chat API call failed", e);
			throw new AiAnalysisException("Ollama API call failed: " + e.getMessage());
		}
	}

	private String handleOllamaResponse(HttpResponse<String> response) throws AiAnalysisException {
		int status = response.statusCode();

		if (status == 404) {
			throw new AiAnalysisException("Ollama model not found (HTTP 404). Pull the model first with 'ollama pull <model>'");
		} else if (status >= 500) {
			throw new AiAnalysisException("Ollama server error (HTTP " + status + ")");
		} else if (status != 200) {
			throw new AiAnalysisException("Ollama API error (HTTP " + status + "): " + response.body());
		}

		try {
			JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
			if (root.has("message")) {
				JsonObject message = root.getAsJsonObject("message");
				if (message.has("content")) {
					return message.get("content").getAsString();
				}
			}
			throw new AiAnalysisException("Unexpected Ollama response format");
		} catch (AiAnalysisException e) {
			throw e;
		} catch (Exception e) {
			throw new AiAnalysisException("Failed to parse Ollama response: " + e.getMessage());
		}
	}
}
