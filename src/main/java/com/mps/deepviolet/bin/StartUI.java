package com.mps.deepviolet.bin;


import javax.swing.SwingUtilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.util.StatusPrinter;

import com.mps.deepviolet.ui.MainFrm;
import com.mps.deepviolet.util.FileUtils;

/**
 * Entry point to start DeepViolet and display a user interface.
 * @author Milton Smith
 *
 */
public class StartUI {
	
	// Must execute before logback initializes
	static {
		
	    // Pass deepviolet report directory to logback to write log file
	    System.setProperty("dv_user_directory", FileUtils.getWorkingDirectory());
		
	}
	
	
    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.bin.StartUI");
	
	/**
	 * Main entry point
	 * @param args Command line arguments (not used for now)
	 */
	public static void main(String[] args) {
		
		new StartUI().init(args);

	}
	
	/**
	 * Initialization
	 */
	private void init(String[] args) {
		

		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
	    ContextInitializer ci = new ContextInitializer(lc);
	    lc.reset();
	    try {
	      ci.autoConfig(); 
	    } catch (JoranException e) {
	      e.printStackTrace();
	    }
	    //StatusPrinter.print(lc);
	    
		logger.info("Starting UI via dvUI");
		
		// Create ~/DeepViolet/ working directory on OS
		FileUtils.createWorkingDirectory();
		
	    SwingUtilities.invokeLater(new Runnable() {
	       public void run() {
	    		MainFrm main = new MainFrm();
	    		main.initComponents();
	    		main.setVisible(true);
	      }
	    });
		
	}
	
	
}
