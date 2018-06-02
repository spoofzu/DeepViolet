package com.mps.deepviolet.api;

import java.util.HashMap;

public class JsonLdrCipherMap extends HashMap<String, JsonLdrClassifications> {

	public JsonLdrCipherMap() {

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public JsonLdrCipherMap(String hexName, JsonLdrClassifications clazz) {
		put(hexName, clazz);
	}
}
