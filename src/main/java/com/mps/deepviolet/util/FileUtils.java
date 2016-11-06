package com.mps.deepviolet.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mps.deepviolet.suite.json.CipherMap;
import com.mps.deepviolet.suite.json.MozillaCerts;

public class FileUtils {

	/**
	 * Get the users DeepViolet working directory. For storing completed
	 * reports.
	 * 
	 * @return Fully qualified name of working directory.
	 */
	public static final String getWorkingDirectory() {

		String OS = System.getProperty("os.name");
		String home = System.getProperty("user.home");

		StringBuffer buff = new StringBuffer();

		if (OS.contains("Linux")) {

			buff.append(home);
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);

		} else if (OS.contains("Windows")) {

			buff.append(home);
			buff.append(File.separator);
			buff.append("My Documents");
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);

		} else if (OS.contains("Mac")) {

			buff.append(home);
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);

		} else {

			// Unknown OS then create in the tmp folder.
			buff.append(System.getProperty("java.io.tmpdir"));
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);

		}

		return buff.toString();
	}

	/**
	 * Create a directory, depending upon the operating system, to store the
	 * results for each scanning run.
	 */
	public static final void createWorkingDirectory() {

		String violetdir = getWorkingDirectory();

		File workdir = new File(violetdir);

		if (workdir.exists()) {
			return;
		}

		if (workdir.exists()) {
			if (!(workdir.canRead() && workdir.canWrite())) {
				System.err.println("Failed creating user report directory, reason=READ&WRITE required");
				System.exit(10);
			}

		}

		if (!workdir.mkdirs()) {
			System.err.println("Can't create a working directory.  reason=File.mkdirs failed");
			System.exit(15);
		}

	}

	public static final String getJsonResourceAsString(String name) {

		//
		// URL ciphermap_url =
		// CipherSuiteUtil.class.getClassLoader().getResource("ciphermap.json");

		BufferedReader br = null;
		StringBuffer buff = new StringBuffer(4000);
		try {
			String sCurrentLine;
			InputStream in = FileUtils.class.getClassLoader().getResourceAsStream(name);
			br = new BufferedReader(new InputStreamReader(in));
			while ((sCurrentLine = br.readLine()) != null) {
				buff.append(sCurrentLine);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (br != null)
					br.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		return buff.toString();
	}

	public static CipherMap readCiphermapFromJSON(String file)
			throws JsonParseException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		CipherMap obj = mapper.readValue(new File(file), CipherMap.class);
		return obj;
	}

	public static MozillaCerts readMozillaCertsFromJSON(String file)
			throws JsonParseException, JsonMappingException, IOException {
		ObjectMapper mapper = new ObjectMapper();
		MozillaCerts obj = mapper.readValue(new File(file), MozillaCerts.class);
		return obj;
	}

}
