package com.mps.deepviolet.api;

import java.io.IOException;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mps.deepviolet.api.JsonLdrCipherMap;
import com.mps.deepviolet.api.JsonLdrClassifications;

public class CipherMapTest {

	@Test
	public void test() throws JsonGenerationException, JsonMappingException, IOException {
		JsonLdrClassifications clazz = new JsonLdrClassifications();
		clazz.setGnuTLS("äsdasdas");
		clazz.setIANA("asdasd");
		clazz.setNSS("asdad");
		JsonLdrCipherMap cm = new JsonLdrCipherMap("0x0_0000", clazz);

		ObjectMapper mapper = new ObjectMapper();
		String jsonInString = mapper.writeValueAsString(cm);
		System.out.println(jsonInString);

	}

}
