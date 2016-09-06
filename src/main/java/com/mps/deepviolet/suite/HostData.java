package com.mps.deepviolet.suite;

import java.net.URL;
import java.util.*;

public class HostData implements ServerMetadata {
	private HashMap<String, Map<String, Object>> featuremap = new HashMap<String, Map<String, Object>>();

	private URL host;
	private long timestamp;
	private static final long TTL = 1000 * 60 * 15; // 15 mins
	
	public HostData( URL url ) {
		this.host = url;
		this.timestamp = System.currentTimeMillis();
	}
	
	public boolean isExpired() {
		return System.currentTimeMillis() > timestamp + TTL;
	}
	
	public void setHost( URL host ) {
		this.host = host;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.suite.ServerMetadataInf#getHost()
	 */
	public URL getHost() {
		return host;
	}
	
	
	void setScalarValue(String feature, String key, String value) {
		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);
		}
		map.put( key, value);
		
	}

	/* (non-Javadoc)
	 * @see com.mps.deepviolet.suite.ServerMetadataInf#getScalarValue(java.lang.String)
	 */
	public String getScalarValue( String feature, String key ) {
		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		return isScalarType(feature, key) ? (String)map.get(key) : null;
		
	}
	
	void setVectorValue(String feature, String key, String[] value) {
		
		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<>();
			featuremap.put(feature, map);	
		}
		
		map.put( key, value );
		
	}
	

	public boolean containsKey(String feature, String key) {

		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<>();
			featuremap.put(feature, map);	
		}
		
		return map.containsKey( key );
		
	}
	

	public List<String> getVectorValue(String feature, String key) {
		
		ArrayList<String> result = new ArrayList<String>();
		
		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<>();
			featuremap.put(feature, map);	
		}
		
		String[] s = (String[])map.get(key);

		Collections.addAll(result, s);
		
		return result;
		
	}

	public List<String> getKeys(String feature) {
		
		ArrayList<String> result = new ArrayList<String>();
		
		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<>();
			featuremap.put(feature, map);	
		}
		
		Set<String> s = map.keySet();
		for (String value : s) {
			result.add(value);
		}
	
		return result;

		
	}
	
	
	public boolean isScalarType(String feature, String key) {

		boolean result = false;
		
		Map<String, Object> map;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<>();
			featuremap.put(feature, map);	
		}
		
		if( map.containsKey( key ) ) {
			result = ( map.get(key) instanceof String );
		}

		return result;
	}
	
	public String toString() {
		
		StringBuilder buff = new StringBuilder(2000);
		
		StringBuilder scalar = new StringBuilder();
		StringBuilder vector = new StringBuilder();

		for (String feature : featuremap.keySet()) {
			List<String> keys = getKeys(feature);
			for(String key : keys) {
				if( isScalarType(feature,key) ) {
					
					String value = getScalarValue(feature, key);
					scalar.append(feature);
					scalar.append(':');
					scalar.append(key);
					scalar.append('=');
					scalar.append(value);
				
				}else{
					
					List<String> values = getVectorValue(feature, key);
					
					vector.append(feature);
					vector.append(':');
					vector.append(key);
					vector.append('=');
					vector.append('{');
					boolean firsttime = true;
					
					for(String value : values) {
						if( !firsttime ) {
							vector.append(',');
						} else {
							firsttime = false;
						}
						vector.append(value);
					}
				
					vector.append('}');
					
				}
			}
		}

		buff.append("Class=").append(this.getClass().getName());
		buff.append(' ');
		buff.append("Instance=").append(this.hashCode());
		buff.append(' ');
		buff.append( "Scalar Values:");
		buff.append(scalar.toString());
		buff.append(' ');
		buff.append("Vector Values:");
		buff.append(vector.toString());	
		buff.append(' ');
		return buff.toString();
	}
	
}
