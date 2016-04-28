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
	private String filename = "";
	
	public volatile boolean bHeader = true;
	public volatile boolean bHostSection = true;
	public volatile boolean bHTTPResponseSection = true;
	public volatile boolean bConnectionSection = true;
	public volatile boolean bCiperSuitSection = true;
	public volatile boolean bServerCertficateSection = true;
	public volatile boolean bCertChainSection = true;
	public volatile boolean bServerAnalysisSection = false;
	public volatile boolean bWriteCertificate = false;
	public volatile boolean bReadCertificate = false;
			
	/**
	 * CTOR
	 * @param url Target URL of TLS scan
	 */
	public DeepScanTask( URL url ) {
		
		this.url = url;
		
	}
	
	/**
	 * CTOR
	 * @param urlTarget URL of TLS scan
	 */
	public DeepScanTask( URL url, String filename ) {
		
		this.url = url;
		this.filename = filename;
		
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
		
		if( bHeader ) {
			
			setStatusBarMessage("Working on Report Header");
   
			DocPrintUtil.printReportHeader(con,url);
   
		}
		
		if( bWriteCertificate ) {
			
			setStatusBarMessage("Writing certificate to disk");
	   		
			DocPrintUtil.writeCertificate(con, url, filename);
			
		}
		
		if( bReadCertificate ) {
			
			setStatusBarMessage("Reading certificate from disk");
	   		
			DocPrintUtil.printServerCertificate(con, filename);
			
		}
		
		if( bHostSection ) {

			setStatusBarMessage("Working on Host Information");
	   		
			DocPrintUtil.printHostInformation(con, url);
		
		}
		
		
		if( bHTTPResponseSection ) {
		
			setStatusBarMessage("Working on Host HTTP Response Headers");
			
			DocPrintUtil.printHostHttpResponseHeaders(con, url);

		}
		
		
		if( bConnectionSection ) {
			
			setStatusBarMessage("Working on Connection Characteristics");

			DocPrintUtil.printConnectionCharacteristics(con, url);
	
		}
		
    
		if( bCiperSuitSection ) {
			
			setStatusBarMessage("Working on Supported Cipher Suites");
   
			DocPrintUtil.printSupportedCipherSuites(con, url);
	
		}
   
		if( bServerCertficateSection ) {
			
			setStatusBarMessage("Working on Server Certificate");
   		
			DocPrintUtil.printServerCertificate(con, url);			

		}
	
		if( bCertChainSection ) {
			
			setStatusBarMessage("Working on Server Certificate Chain");

			DocPrintUtil.printServerCertificateChain(con, url);
		
		}
		
		if( bServerAnalysisSection ) {
		
			setStatusBarMessage("Working on Server Analysis");

			DocPrintUtil.printServerAnalysis(con, url);
		
		}
	}
	

}
