package com.mps.deepviolet.api;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mps.deepviolet.api.JsonLdrCipherMap;
import com.mps.deepviolet.api.JsonLdrConfiguration;
import com.mps.deepviolet.api.JsonLdrMozillaCerts;
import com.mps.deepviolet.util.FileUtils;

public class FileUtilsTest {

	@Test
	public void testReadCiphermapFromJSON() throws JsonParseException, JsonMappingException, IOException {
		JsonLdrCipherMap map = FileUtils.readCiphermapFromJSON("./src/main/resources/ciphermap.json");
		assertNotNull(map);
		JsonLdrMozillaCerts certs = FileUtils.readMozillaCertsFromJSON("./src/main/resources/server-side-tls-conf-4.0.json");
		assertNotNull(certs);
	}

	@Test
	public void testWriteMozillaJSON() throws JsonProcessingException {
		JsonLdrMozillaCerts certs = new JsonLdrMozillaCerts();
		certs.setHref("http://labla");
		Map<String, JsonLdrConfiguration> configs = new HashMap<>();
		JsonLdrConfiguration config1 = new JsonLdrConfiguration();
		config1.setOpenssl_ciphersuites("lot of ebc and so on");
		configs.put("moden", config1);
		JsonLdrConfiguration config2 = new JsonLdrConfiguration();
		config2.setOpenssl_ciphersuites("lot of ebc and cbc and so on");
		configs.put("mdedium", config2);
		certs.setConfigurations(configs);
		ObjectMapper mapper = new ObjectMapper();
		String jsonInString = mapper.writeValueAsString(certs);
		jsonInString = mapper.writeValueAsString(certs);
		System.out.println(jsonInString);

	}

}
