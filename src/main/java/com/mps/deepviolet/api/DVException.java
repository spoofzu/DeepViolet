package com.mps.deepviolet.api;

/**
 * Base exception class for DeepViolet API
 * @author Milton Smith
 */
public class DVException extends Exception {

		private static final long serialVersionUID = -5786798156737779391L;

		/**
		 * CTOR
		 */
		public DVException() {
			super();
		}

		/**
		 * CTOR
		 * @param message Error message
		 */
	 	public DVException(String message) {
	 		super(message);
	 	}

		/**
		 * CTOR
		 * @param message Error message
		 * @param cause Related system exception
		 */
	 	public DVException(String message, Throwable cause) {
	 		super(message, cause);
	 	}
	
		/**
		 * CTOR
		 * @param cause Related system exception
		 */
	 	public DVException(Throwable cause ) {
	 		super(cause);
	 	}
}
