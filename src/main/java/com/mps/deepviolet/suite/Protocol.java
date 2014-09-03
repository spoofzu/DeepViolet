package com.mps.deepviolet.suite;

import java.util.HashMap;
import java.util.Map.Entry;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Protocol {
	
	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.suite.Protocol");
	
	private String name;
	
	private HashMap<String,Object> mciphers = new HashMap<String,Object>();
	
	public Protocol( String name ) {
		
		this.name = name;
		
	}
	
	public String getName() {
		
		return name;
		
	}
	
	public void addCipher( String cipher ) {
		
		mciphers.put(cipher, null);
		
	}
	
	public String[] getCiphers() {
		
		return (String[])mciphers.keySet().toArray(new String[0]);
		
		
	}
	
	public boolean hasCipher( String cipher ) {
		
		return mciphers.containsKey(cipher);
		
	}
	 
}
