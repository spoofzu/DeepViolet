package com.mps.deepviolet.api.ai;

/**
 * A single message in a multi-turn AI chat conversation.
 *
 * @param role    message role ("user", "assistant", or "system")
 * @param content message text
 * @author Milton Smith
 */
public record AiChatMessage(String role, String content) {}
