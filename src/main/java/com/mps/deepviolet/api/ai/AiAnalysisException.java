package com.mps.deepviolet.api.ai;

/**
 * Exception for AI analysis failures (auth, rate limit, network, parse).
 *
 * @author Milton Smith
 */
public class AiAnalysisException extends Exception {

	public AiAnalysisException(String message) {
		super(message);
	}

	public AiAnalysisException(String message, Throwable cause) {
		super(message, cause);
	}
}
