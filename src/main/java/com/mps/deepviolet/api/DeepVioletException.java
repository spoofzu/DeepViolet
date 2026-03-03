package com.mps.deepviolet.api;

/**
 * Base exception class for DeepViolet API
 * @author Milton Smith
 */
public class DeepVioletException extends Exception {

		private static final long serialVersionUID = -5786798156737779391L;

		/**
		 * CTOR
		 */
		public DeepVioletException() {
			super();
		}

		/**
		 * CTOR
		 * @param message Error message
		 */
	 	public DeepVioletException(String message) {
	 		super(message);
	 	}

		/**
		 * CTOR
		 * @param message Error message
		 * @param cause Related system exception
		 */
	 	public DeepVioletException(String message, Throwable cause) {
	 		super(message, cause);
	 	}
	
		/**
		 * CTOR
		 * @param cause Related system exception
		 */
	 	public DeepVioletException(Throwable cause ) {
	 		super(cause);
	 	}
}
