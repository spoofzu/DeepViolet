package com.mps.deepviolet.job;

import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.suite.CipherSuiteUtil;
import com.mps.deepviolet.suite.ServerMetadata;
import com.mps.deepviolet.ui.DocPrintUtil;

/**
 * Coordinates the order and execution of scan tasks
 * @author Milton Smith
 */
public class DeepScanTask extends UIBackgroundTask {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.job.UIBackgroundTask");
	
	protected volatile StringBuffer con = new StringBuffer();	
	
	private URL url;
	
	/**
	 * CTOR
	 * @param url
	 */
	public DeepScanTask( URL url ) {
		
		this.url = url;
		
	}
	
	/**
	 * Return the current URL
	 * @return
	 */
	public URL getURL() {
		
		return url;
		
	}
	
	/**
	 * Retrieve the status message for each task to communicate
	 * on the UI to users
	 * @return String Status message.
	 */
	public String getLargeStatusMessage() {
		
		return con.toString();
		
	}
	
	/**
	 * Execute sections of a scan report.  Set the status bar message on
	 * each step for the user
	 */
	protected  void doInBackground() throws Exception {
		
		setStatusBarMessage("Working on Report Header");
   
		DocPrintUtil.printReportHeader(con,url);
   
		

		setStatusBarMessage("Working on Host Information");
   		
		DocPrintUtil.printHostInformation(con, url);
		
		
		
		setStatusBarMessage("Working on Host HTTP Response Headers");
		
		DocPrintUtil.printHostHttpResponseHeaders(con, url);

		
		
		setStatusBarMessage("Working on Connection Characteristics");

		DocPrintUtil.printConnectionCharacteristics(con, url);
	
		
    
		setStatusBarMessage("Working on Supported Cipher Suites");
   
		DocPrintUtil.printSupportedCipherSuites(con, url);
	
	  
   
		setStatusBarMessage("Working on Server Certificate");
   
		DocPrintUtil.printServerCertificate(con, url);

 	
	
		setStatusBarMessage("Working on Server Certificate Chain");

		DocPrintUtil.printServerCertificateChain(con, url);
		
		
		
		setStatusBarMessage("Working on Server Analysis");

		DocPrintUtil.printServerAnalysis(con, url);
		
	}
	

}
