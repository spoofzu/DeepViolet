package com.mps.deepviolet.suite;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.mps.deepviolet.suite.CipherMap;
import com.mps.deepviolet.util.FileUtils;

public class FileUtilsTest {

	@Test
	public void testReadCiphermapFromJSON() throws JsonParseException, JsonMappingException, IOException {
		CipherMap map = FileUtils.readCiphermapFromJSON("./src/main/resources/ciphermap.json");
		assertNotNull(map);
	}

}
