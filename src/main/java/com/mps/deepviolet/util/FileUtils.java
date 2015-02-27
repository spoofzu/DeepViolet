package com.mps.deepviolet.util;

import java.io.File;

public class FileUtils {

	/**
	 * Create a directory, depending upon the operating system, to store
	 * the results for each scanning run.
	 */
	public static void createWorkingDirectory() {
		
		String OS = System.getProperty("os.name");
		String home = System.getProperty("user.home");
		
		StringBuffer buff = new StringBuffer();
		
		if ( OS.contains("Linux") ) {
			
			buff.append(home);
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);
			
		} else if( OS.contains("Windows")) {
			
			buff.append(home);
			buff.append(File.separator);
			buff.append("My Documents");
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);
			
		} else if( OS.contains("Mac") ) {
			
			buff.append(home);
			buff.append(File.separator);
			buff.append("DeepViolet");
			buff.append(File.separator);
			
		} else {
			
			System.err.println("Can't create a working directory.  reason=Unknown OS type");
			System.exit(1);
			
		}
		
		File workdir = new File(buff.toString());
		
		if( workdir.exists() ) {
			return;
		}
		
		
		if ( workdir.mkdir() ) {
			
			System.err.println("Can't create a working directory.  reason=File.mkdir failed");
			System.exit(3);
		}
		
		
	}
	
}
