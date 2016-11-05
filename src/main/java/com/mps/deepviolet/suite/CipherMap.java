package com.mps.deepviolet.suite;

import java.util.HashMap;

public class CipherMap extends HashMap<String, Classifications> {

	public CipherMap() {

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public CipherMap(String hexName, Classifications clazz) {
		put(hexName, clazz);
	}
}
