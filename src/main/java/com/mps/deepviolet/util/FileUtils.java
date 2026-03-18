package com.mps.deepviolet.util;

import java.io.File;

/** Utility methods for DeepViolet file and directory operations. */
public class FileUtils {

	/** Creates a FileUtils instance. */
	public FileUtils() {}

	/**
	 * Get the users DeepViolet working directory. For storing completed
	 * reports.
	 *
	 * @return Fully qualified name of working directory.
	 */
	public static final String getWorkingDirectory() {

		String OS = System.getProperty("os.name");
		String home = System.getProperty("user.home");

		StringBuilder buff = new StringBuilder();

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

}
