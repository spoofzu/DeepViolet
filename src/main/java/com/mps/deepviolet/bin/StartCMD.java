package com.mps.deepviolet.bin;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.swing.Timer;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.core.util.StatusPrinter;

import com.mps.deepviolet.job.DeepScanTask;
import com.mps.deepviolet.util.FileUtils;

/**
 * Entry point to start DeepViolet and run headless.  Useful for running
 * DeepViolet from scripts.
 * @author Milton Smith
 *
 */
public class StartCMD {
	
	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.bin.StartCMD");

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		new StartCMD().init(args);
		
	}

	/**
	 * Initialization
	 */
	private void init(String[] args) {
		
	    LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
	    StatusPrinter.print(lc);
		logger.info("Starting headless");
		
		int err = 0;
		
		try {

			// Create command line options
			Options options = new Options();
			options.addOption( "u", "serverurl", true, "HTTPS server URL to scan" );
			
			CommandLineParser p = new BasicParser();
			CommandLine cmdline = null;
			
			try {
				cmdline = p.parse(options,args);
			}catch(ParseException e){
				err = 1;
				throw e;
			}
			
			if (cmdline == null ) {
				err = 2;
				throw new Exception( "Null cmdline returned from parse.");
			}
				

			if ( !cmdline.hasOption("u") ) {
				err=3;
				throw new Exception( "No HTTPS server specified." );
			}
			
			
			// Create ~/DeepViolet/ working directory on OS
			FileUtils.createWorkingDirectory();
						
		   // Background SSL scanning thread
				
		   final DeepScanTask st = new DeepScanTask(new URL(cmdline.getOptionValue("u"))); 
		   st.start();
		   
		   updateLongRunningCMDStatus( st ); 
		  
		} catch (Throwable t ) {

			logger.error(t.getMessage(), t);
			System.exit(1);
		}
		
	}

	/**
	 * Update tick every 5 seconds
	 * @param task
	 */
	private void updateLongRunningCMDStatus( final DeepScanTask task ) {
		
	   // Background update thread.  Display scan results in progress
	   final int delay = 5000; //Update interval
	   ActionListener taskPerformer = new ActionListener() {
		   int ct = 0;
		   public void actionPerformed(ActionEvent evt) {
			   if( task.isWorking() ) {
				   ct += delay;
				   logger.info("Still busy, "+ct/1000+" seconds elapsed."); 
			   } else {  	    	
		    		logger.info( "Processing for url="+task.getURL().toString()+" is complete, finished.");
					// Scan done, stop timer.
		    	    ((Timer)evt.getSource()).stop();
			   }	
		   }
		};
		new Timer(delay, taskPerformer).start();
		
	}
	
}

