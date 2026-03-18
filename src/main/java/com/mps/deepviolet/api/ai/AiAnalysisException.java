package com.mps.deepviolet.api.ai;

/**
 * Exception for AI analysis failures (auth, rate limit, network, parse).
 *
 * @author Milton Smith
 */
public class AiAnalysisException extends Exception {

	/**
	 * Creates an exception with the given message.
	 *
	 * @param message detail message
	 */
	public AiAnalysisException(String message) {
		super(message);
	}

	/**
	 * Creates an exception with the given message and cause.
	 *
	 * @param message detail message
	 * @param cause underlying cause
	 */
	public AiAnalysisException(String message, Throwable cause) {
		super(message, cause);
	}
}
