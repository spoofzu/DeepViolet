package com.mps.deepviolet.api;

import java.net.URL;
import java.util.List;

/**
 * Interface for accessing server metadata organized by feature and key.
 * Supports scalar (String) and vector (String[]) values with cache expiration.
 */
interface ServerMetadata {

	public URL getHost();
	
	public boolean isExpired();

	public  String getScalarValue(String feature, String key);

	public List<String> getVectorValue(String feature, String key);

	public boolean containsKey(String feature, String key);
	
	public List<String> getKeys(String feature);
	
	public boolean isScalarType(String feature, String key);
	
	public String toString();

}