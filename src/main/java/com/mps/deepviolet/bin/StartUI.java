package com.mps.deepviolet.bin;


import javax.swing.SwingUtilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.core.util.StatusPrinter;

import com.mps.deepviolet.ui.MainFrm;
import com.mps.deepviolet.util.FileUtils;

/**
 * Entry point to start DeepViolet and display a user interface.
 * @author Milton Smith
 *
 */
public class StartUI {

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
		
		// Create ~/DeepViolet/ working directory on OS
		FileUtils.createWorkingDirectory();
		
	    LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
	    StatusPrinter.print(lc);
		
		logger.info("Starting UI");
		
	    SwingUtilities.invokeLater(new Runnable() {
	       public void run() {
	    		MainFrm main = new MainFrm();
	    		main.initComponents();
	    		main.setVisible(true);
	      }
	    });
		
	}
	
	
}
