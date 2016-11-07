package com.mps.deepviolet.suite;

import java.io.IOException;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mps.deepviolet.suite.CipherMap;
import com.mps.deepviolet.suite.Classifications;

public class CipherMapTest {

	@Test
	public void test() throws JsonGenerationException, JsonMappingException, IOException {
		Classifications clazz = new Classifications();
		clazz.setGnuTLS("äsdasdas");
		clazz.setIANA("asdasd");
		clazz.setNSS("asdad");
		CipherMap cm = new CipherMap("0x0_0000", clazz);

		ObjectMapper mapper = new ObjectMapper();
		String jsonInString = mapper.writeValueAsString(cm);
		System.out.println(jsonInString);

	}

}
