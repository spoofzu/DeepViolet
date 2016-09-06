package com.mps.deepviolet.suite;

import java.net.URL;
import java.util.List;

public interface ServerMetadata {

	URL getHost();
	
	boolean isExpired();

	String getScalarValue(String feature, String key);

	List<String> getVectorValue(String feature, String key);

	boolean containsKey(String feature, String key);
	
	List<String> getKeys(String feature);
	
	boolean isScalarType(String feature, String key);
	
	String toString();

}