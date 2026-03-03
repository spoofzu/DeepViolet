package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

import com.mps.deepviolet.util.FileUtils;

public class FileUtilsTest {

	@Test
	public void testGetWorkingDirectoryNotEmpty() {
		String dir = FileUtils.getWorkingDirectory();
		assertNotNull(dir);
		assertFalse(dir.isEmpty());
		assertTrue(dir.contains("DeepViolet"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testCiphermapYamlOnClasspath() {
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("ciphermap.yaml")) {
			assertNotNull(is, "ciphermap.yaml should be on classpath");

			LoadSettings settings = LoadSettings.builder().build();
			Load load = new Load(settings);
			Map<String, Object> root = (Map<String, Object>) load.loadFromInputStream(is);

			assertTrue(root.containsKey("metadata"), "YAML should have metadata");
			assertTrue(root.containsKey("cipher_suites"), "YAML should have cipher_suites");

			Map<String, Object> metadata = (Map<String, Object>) root.get("metadata");
			assertEquals("1.0", metadata.get("version"));
		} catch (Exception e) {
			fail("Failed to load ciphermap.yaml: " + e.getMessage());
		}
	}
}
