package com.mps.deepviolet.api;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

class HostData implements ServerMetadata {
	
	private HashMap<String, HashMap<String, Object>> featuremap = new HashMap<String, HashMap<String, Object>>();
	
	//private HashMap<String, Object> map = new HashMap<String, Object>();
	
	private URL host;
	
	private long timestamp;
	
	private long TTL = 1000 * 60 * 15; // 15 mins 
	
	public HostData( URL url ) {
		
		this.host = url;
		
		this.timestamp = System.currentTimeMillis();
		
	}
	
	public boolean isExpired() {
		
		return System.currentTimeMillis() > timestamp + TTL;
		
	}
	
	public void setHost( URL host ) {
		
		this.host=host;
	}
	
	/* (non-Javadoc)
	 * @see com.mps.deepviolet.suite.ServerMetadataInf#getHost()
	 */
	public URL getHost() {
		
		return host;
	}
	
	
	public void setScalarValue( String feature, String key, String value ) {
		
		HashMap<String, Object> map = null;
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
		
		HashMap<String, Object> map = null;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		
		return isScalarType(feature, key) ? (String)map.get(key) : null;
		
	}
	
	public void setVectorValue( String feature, String key, String[] value ) {
		
		HashMap<String, Object> map = null;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		
		map.put( key, value );
		
	}
	

	public boolean containsKey(String feature, String key) {

		HashMap<String, Object> map = null;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		
		return map.containsKey( key );
		
	}
	

	public List<String> getVectorValue(String feature, String key) {
		
		ArrayList<String> result = new ArrayList<String>();
		
		HashMap<String, Object> map = null;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		
		String[] s = (String[])map.get(key);
		
		for( String val : s )
			result.add(val);
		
		return result;
		
	}

	public List<String> getKeys(String feature) {
		
		ArrayList<String> result = new ArrayList<String>();
		
		HashMap<String, Object> map = null;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		
		Set<String> s = map.keySet();
		
		Iterator<String> i = s.iterator();
		
		while ( i.hasNext() )
			result.add( i.next() );
	
		return result;

		
	}
	
	
	public boolean isScalarType(String feature, String key) {

		boolean result = false;
		
		HashMap<String, Object> map = null;
		if( featuremap.containsKey(feature) ) {
			map = featuremap.get(feature);
		} else {
			map = new HashMap<String, Object>();
			featuremap.put(feature, map);	
		}
		
		if( map.containsKey( key ) )
			result = ( map.get(key) instanceof String );
		
		return result;
		
	}
	
	public String toString() {
		
		StringBuffer buff = new StringBuffer(2000);
		
		StringBuffer scalar = new StringBuffer();
		StringBuffer vector = new StringBuffer();
	
		Iterator<String> fi = featuremap.keySet().iterator();
		
		while ( fi.hasNext() ) {
			
			String feature = fi.next();
		
			List<String> keys = getKeys(feature);
			Iterator<String> i = keys.iterator();
			
			while ( i.hasNext() ) {
				
				String key = i.next();
				
				if( isScalarType(feature,key) ) {
					
					String value = getScalarValue(feature, key);
					scalar.append(feature);
					scalar.append(':');
					scalar.append(key);
					scalar.append('=');
					scalar.append(value);
				
				}else{
					
					List<String> values = getVectorValue(feature, key);
					Iterator<String> v = values.iterator();
					
					vector.append(feature);
					vector.append(':');
					vector.append(key);
					vector.append('=');
					vector.append('{');
					boolean firsttime = true;
					
					while( v.hasNext() ) {
						
						String value = v.next();
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
			
		buff.append("Class="+this.getClass().getName());
		buff.append(' ');
		buff.append("Instance="+this.hashCode());
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
