package com.mps.deepviolet.util;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileUtils {

	/**
	 * Get the users DeepViolet working directory.  For storing completed reports.
	 * @return Fully qualified name of working directory.
	 */
	public static final String getWorkingDirectory() {
		
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

			// Unknown OS then create in the tmp folder.
			buff.append( System.getProperty("java.io.tmpdir") );
		    buff.append( File.separator );
			buff.append( "DeepViolet" );
			buff.append( File.separator );
			
		}
		
		return buff.toString();
	}
	
	/**
	 * Create a directory, depending upon the operating system, to store
	 * the results for each scanning run.
	 */
	public static final void createWorkingDirectory() {

		String violetdir = getWorkingDirectory();
		
		File workdir = new File(violetdir);
		
		if( workdir.exists() ) {
			return;
		} 
		
		if( workdir.exists() ) {	
			if( !(workdir.canRead() && workdir.canWrite()) ) {
				System.err.println("Failed creating user report directory, reason=READ&WRITE required");
				System.exit(10);
			}
			
		}
		
		if ( !workdir.mkdirs() ) {	
			System.err.println("Can't create a working directory.  reason=File.mkdirs failed");
			System.exit(15);
		}
		
		
	}
	
}
