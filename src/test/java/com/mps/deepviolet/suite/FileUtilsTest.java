package com.mps.deepviolet.suite;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mps.deepviolet.suite.json.CipherMap;
import com.mps.deepviolet.suite.json.Configuration;
import com.mps.deepviolet.suite.json.MozillaCerts;
import com.mps.deepviolet.util.FileUtils;

public class FileUtilsTest {

	@Test
	public void testReadCiphermapFromJSON() throws JsonParseException, JsonMappingException, IOException {
		CipherMap map = FileUtils.readCiphermapFromJSON("./src/main/resources/ciphermap.json");
		assertNotNull(map);
		MozillaCerts certs = FileUtils.readMozillaCertsFromJSON("./src/main/resources/server-side-tls-conf-4.0.json");
		assertNotNull(certs);
	}

	@Test
	public void testWriteMozillaJSON() throws JsonProcessingException {
		MozillaCerts certs = new MozillaCerts();
		certs.setHref("http://labla");
		Map<String, Configuration> configs = new HashMap<>();
		Configuration config1 = new Configuration();
		config1.setOpenssl_ciphersuites("lot of ebc and so on");
		configs.put("moden", config1);
		Configuration config2 = new Configuration();
		config2.setOpenssl_ciphersuites("lot of ebc and cbc and so on");
		configs.put("mdedium", config2);
		certs.setConfigurations(configs);
		ObjectMapper mapper = new ObjectMapper();
		String jsonInString = mapper.writeValueAsString(certs);
		jsonInString = mapper.writeValueAsString(certs);
		System.out.println(jsonInString);

	}

}
