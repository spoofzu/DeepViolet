package com.mps.deepviolet.util;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;
import ch.qos.logback.core.joran.spi.JoranException;

/**
 * Helper class to initialize the logback logger.
 * @author Milton Smith
 *
 */
public class LogUtils {

	public static final void logInit() {
		
		// Assign some variables to the logback log
		System.setProperty("dv_user_directory", FileUtils.getWorkingDirectory());
		System.setProperty("dv_user_level", "INFO");
		
	    // Pass deepviolet report directory to logback to write log file
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
	    ContextInitializer ci = new ContextInitializer(lc);
	    lc.reset();
	    try {
	      ci.autoConfig(); 
	    } catch (JoranException e) {
	      e.printStackTrace();
	    }
	    //StatusPrinter.print(lc);
		    
	}
	
}
