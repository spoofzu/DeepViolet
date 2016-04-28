package com.mps.deepviolet.bin;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.swing.Timer;

import org.apache.commons.cli.BasicParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;
import ch.qos.logback.core.joran.spi.JoranException;

import com.mps.deepviolet.job.DeepScanTask;
import com.mps.deepviolet.util.FileUtils;

/**
 * Entry point to start DeepViolet and run headless.  Useful for running
 * DeepViolet from scripts.
 * @author Milton Smith
 *
 */
public class StartCMD {
	
	// Must execute before logback initializes
	static {
		
	    System.setProperty("dv_user_directory", FileUtils.getWorkingDirectory());
	    
	}
	
	public static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.bin.StartCMD");
	
	private static final String EOL = System.getProperty("line.separator");
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub

		new StartCMD().init(args);
		
	}

	/**
	 * Initialization
	 */
	private void init(String[] args) {
		
	    // Pass deepviolet report directory to logback to write log file
	    System.setProperty("dv_user_directory", FileUtils.getWorkingDirectory());
		LoggerContext lc = (LoggerContext) LoggerFactory.getILoggerFactory();
	    ContextInitializer ci = new ContextInitializer(lc);
	    lc.reset();
	    try {
	      ci.autoConfig(); 
	    } catch (JoranException e) {
	      e.printStackTrace();
	    }
	    //StatusPrinter.print(lc);
	    
	    logger.info("Starting headless via dvCMD");
		
		// Create ~/DeepViolet/ working directory on OS
	    FileUtils.createWorkingDirectory();
	    
		int err = 0;
		
		try {

			// Create command line options
			Options options = new Options();
			options.addOption("wc", "writecertificate", true, "Optional, write PEM encoded certificate to disk. Ex: -wc ~/certs/mycert.pem");
			options.addOption("s", "sections", true, "Optional, unspecified prints all sections or specify sections. [t|h|r|c|i|s|n]");
			
			// Mutually exclusive options
			OptionGroup certsource = new OptionGroup();	
			certsource.addOption(new Option("h", "help", false, "Optional, print dvCMD help options."));
			certsource.addOption(new Option("u", "serverurl", true, "Required for all options except -readcertificate, HTTPS server URL to scan."));
			certsource.addOption(new Option("rc", "readcertificate", true, "Optional, read PEM encoded certificate from disk. Ex: -rc ~/certs/mycert.pem"));
			certsource.setRequired(true);
			options.addOptionGroup(certsource);
			
			CommandLineParser p = new BasicParser();
			CommandLine cmdline = null;
			
			try {
				cmdline = p.parse(options,args);
			}catch(ParseException e){
				logger.error(e.getMessage());
				System.exit(-1);
			}
			
			if (cmdline == null ) {
				logger.error( "Null cmdline returned from parse, exiting.");
				System.exit(-1);
			}

			if ( !cmdline.hasOption("u") ) {
				if( !cmdline.hasOption("h") && !cmdline.hasOption("rc")) {
					logger.error( "No HTTPS server specified, exiting.");
					System.exit(-1);
				}
			} else {
				
				String host = cmdline.getOptionValue('u');
				if( !host.startsWith("https") ) {
					logger.error( "Requires URL scheme type, HTTPS, exiting.");
					System.exit(-1);
				}
			}
						
		   // print help options
		   if( cmdline.hasOption("h") ) {
			   // Generate help options
			   
			   StringBuffer hm = new StringBuffer();
			   hm.append( "java -jar dvCMD.jar -serverurl <host|ip> [-wc <file> | -rc <file>] [-h -s{t|h|r|c|i|s|n}]"+EOL );
			   hm.append( "Ex: dvCMD.jar -serverurl https://www.host.com/ -sections ts"+EOL );
			   hm.append( "Where sections are the following,"+EOL);
			   hm.append( "t=header section, h=host section, r=http response section,"+EOL);
			   hm.append( "c=connection characteristics section, i=ciphersuite section,"+EOL);
			   hm.append( "s=server certificate section, n=certificate chain section"+EOL);
			   hm.append(""+EOL);
			   
			   HelpFormatter formatter = new HelpFormatter();
			   formatter.printHelp( hm.toString(), options );
			   
			   System.exit(-1);
		   }
			
		   // Background SSL scanning thread
		   String filename = cmdline.hasOption("rc") ? cmdline.getOptionValue("rc") : cmdline.getOptionValue("wc");
		   URL url = cmdline.hasOption("u") ? new URL(cmdline.getOptionValue("u")) : null;
		   final DeepScanTask st =  new DeepScanTask(url, filename); 
		   
		   st.bReadCertificate = cmdline.hasOption("rc");
		   st.bWriteCertificate = cmdline.hasOption("wc");
		   
		   // grab all section options
		   String section_options = cmdline.getOptionValue("s");
		   
		   // If no sections specified default to all
		   if( !cmdline.hasOption("s")  ) {
			   
			   // Unless we are writing a certificate to a file.
			   // In which case we default to no sections.
		       if( cmdline.hasOption("wc") ) {
				   // Print header section
				   st.bHeader = true; // URL not required
				   st.bHostSection = false;
				   st.bHTTPResponseSection = false;
				   st.bConnectionSection = false;
				   st.bCiperSuitSection = false;
				   st.bServerCertficateSection = false;
				   st.bCertChainSection = false;
				   st.bReadCertificate = false;
		       } else if ( cmdline.hasOption("rc") ) {
		    	   st.bHeader = false;
				   st.bHostSection = false;
				   st.bHTTPResponseSection = false;
				   st.bConnectionSection = false;
				   st.bCiperSuitSection = false;
				   st.bServerCertficateSection = false; // requires URL
				   st.bReadCertificate = true;
				   st.bCertChainSection = false;
		       } else {
		    	   st.bHeader = true;
				   st.bHostSection = true;
				   st.bHTTPResponseSection = true;
				   st.bConnectionSection = true;
				   st.bCiperSuitSection = true;
				   st.bServerCertficateSection = true;
				   st.bCertChainSection = true;
				   st.bReadCertificate = false;
		       }
  
		   // Sections are specified
		   } else {
	
			   // If certificate is being read from file fail on s settings
			   if( !cmdline.hasOption("rc") ) {
			   
				   // s options=thrcisn
				   
				   // Print header section
				   st.bHeader = section_options.lastIndexOf('t')>-1;
				   
				   // Print host section
				   st.bHostSection = section_options.lastIndexOf('h')>-1;
				   
				   // Print HTTP response header section
				   st.bHTTPResponseSection = section_options.lastIndexOf('r')>-1;
				   
				   // Print connections characteristics section
				   st.bConnectionSection = section_options.lastIndexOf('c')>-1;
				   
				   // Print supported cipher suites section
				   st.bCiperSuitSection = section_options.lastIndexOf('i')>-1;
				   
				   // Print server certificate section 
				   st.bServerCertficateSection = section_options.lastIndexOf('s')>-1;
				   
				   // Print server certificate chain section 
				   st.bCertChainSection = section_options.lastIndexOf('n')>-1;
				   
				   // Print server certificate chain section 
				   st.bReadCertificate = false;
			   
			   } else {
				   
					logger.error( "'rc' option and 's' option are mutually exclusive, exiting.");
					System.exit(-1);
			   }
		   
		   }
		
		   // Fire up the worker thread and update status
		   long start = System.currentTimeMillis();
		   
		   st.start();	   
		   updateLongRunningCMDStatus( st ); 
		  
		   // Block until background thread completes.
		   while( st.isWorking() ) {
			   Thread.yield();
		   }
		   
		   long finish = System.currentTimeMillis();
		   logger.info( "");
		   logger.info( "Processing complete, execution(ms)="+(finish-start));
		   
		} catch (Throwable t ) {

			logger.error(t.getMessage(), t);
			System.exit(-1);
		}
		
	}

	/**
	 * Update tick every 5 seconds
	 * @param task
	 */
	private void updateLongRunningCMDStatus( final DeepScanTask task ) {
		
		// Instance logger.  Need to define working dir before we can create.
	   final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.bin.StartCMD");
		
	   // Background update thread.  Display scan results in progress
	   final int delay = 5000; //Update interval
	   ActionListener taskPerformer = new ActionListener() {
		   int ct = 0;
		   public void actionPerformed(ActionEvent evt) {
			   if( task.isWorking() ) {
				   ct += delay;
				   logger.info("Still busy, "+ct/1000+" seconds elapsed."); 
			   } else {  	    	
					// Scan done, stop timer.
		    	    ((Timer)evt.getSource()).stop();
			   }	
		   }
		};
		new Timer(delay, taskPerformer).start();
		
		
	}
	
}

