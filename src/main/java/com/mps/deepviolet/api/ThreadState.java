package com.mps.deepviolet.api;

/**
 * Represents the current state of a scanner thread.
 *
 * @author Milton Smith
 */
public enum ThreadState {

	/** Actively running a scan section. */
	EXECUTING,

	/** In per-host section delay. */
	SLEEPING,

	/** Waiting for next host assignment. */
	IDLE
}
