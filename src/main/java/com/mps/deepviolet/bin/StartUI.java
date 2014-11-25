package com.mps.deepviolet.bin;


/**
 * Entry point to start DeepViolet as desktop application.
 * @author Milton Smith
 */
import java.io.File;

import javax.swing.SwingUtilities;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.core.util.StatusPrinter;

import com.mps.deepviolet.ui.MainFrm;

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
		createWorkingDirectory();
		
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
	
	/**
	 * Create a directory, depending upon the operating system, to store
	 * the results for each scanning run.
	 */
	private void createWorkingDirectory() {
		
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
