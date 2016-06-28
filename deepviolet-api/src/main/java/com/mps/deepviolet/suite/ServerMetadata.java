package com.mps.deepviolet.suite;

import java.net.URL;
import java.util.List;

public interface ServerMetadata {

	public URL getHost();
	
	public boolean isExpired();

	public  String getScalarValue(String feature, String key);

	public List<String> getVectorValue(String feature, String key);

	public boolean containsKey(String feature, String key);
	
	public List<String> getKeys(String feature);
	
	public boolean isScalarType(String feature, String key);
	
	public String toString();

}