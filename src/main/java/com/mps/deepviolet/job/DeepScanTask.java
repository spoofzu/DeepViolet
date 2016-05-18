package com.mps.deepviolet.job;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVOnEng;
import com.mps.deepviolet.api.DVException;

import com.mps.deepviolet.api.IDVOffEng;
import com.mps.deepviolet.api.IDVOffPrint;
import com.mps.deepviolet.api.IDVOnPrint;
import com.mps.deepviolet.api.IDVSession;

/**
 * Coordinates the order and execution of scan tasks
 * @author Milton Smith
 */
public class DeepScanTask extends UIBackgroundTask {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.job.UIBackgroundTask");
	
	protected volatile StringBuffer con = new StringBuffer();	
	
	private IDVOnPrint p;
	private IDVOffPrint op;
	private IDVOffEng oeng;
	private IDVOnEng eng;
	private URL url;
	private String filename;
	
	public volatile boolean bHeader = true;
	public volatile boolean bHostSection = true;
	public volatile boolean bHTTPResponseSection = true;
	public volatile boolean bConnectionSection = true;
	public volatile boolean bCiperSuitSection = true;
	public volatile boolean bServerCertficateSection = true;
	public volatile boolean bCertChainSection = true;
	//public volatile boolean bServerAnalysisSection = false;
	public volatile boolean bWriteCertificate = false;
	public volatile boolean bReadCertificate = false;
			
	/**
	 * CTOR
	 * @param url Target URL of TLS scan
	 * @throws DVException thrown on host initialization problems
	 */
	public DeepScanTask( URL url ) throws DVException {
		
		this( url, "");
		
	}
	
	/**
	 * CTOR
	 * @param url Target URL of TLS scan
	 * @param filename Filename to save offline reports
	 * @throws DVException thrown on host initialization problems
	 */
	public DeepScanTask( URL url, String filename ) throws DVException {
		
		this.url = url;
		this.filename = filename;

		IDVSession session = null;
		if( url == null ) {
			// Supports initializing for offline use.  For example, read/write pem files
			oeng = DVFactory.getDVOffEng();
			op = oeng.getDVOffPrint();
		} else {
			session = DVFactory.initializeSession(url);
			eng = DVFactory.getDVEng(session);
			p = eng.getDVOnPrint(con);
		}


	}
	
	/**
	 * Return the current URL
	 * @return Host URL
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
   
			p.printReportHeader();
   
		}
		
		if( bWriteCertificate ) {
			
			setStatusBarMessage("Writing certificate to disk");
	   		
			try {
				eng.writeCertificate( filename);
			}catch( DVException e ) {
				String err = "Error writing certificate to disk. msg="+e.getMessage();
				p.println(err);
				logger.error(err,e);
			}
			
		}
		
		if( bReadCertificate ) {
			
			setStatusBarMessage("Reading certificate from disk");
	   		
			op.printCertificate(filename);

			
		}
		
		if( bHostSection ) {

			setStatusBarMessage("Working on Host Information");
	   		
			p.printHostInformation();
		
		}
		
		
		if( bHTTPResponseSection ) {
		
			setStatusBarMessage("Working on Host HTTP Response Headers");
			
			p.printHostHttpResponseHeaders();

		}
		
		
		if( bConnectionSection ) {
			
			setStatusBarMessage("Working on Connection Characteristics");

			p.printConnectionCharacteristics();
	
		}
		
    
		if( bCiperSuitSection ) {
			
			setStatusBarMessage("Working on Supported Cipher Suites");
   
			p.printSupportedCipherSuites();
	
		}
   
		if( bServerCertficateSection ) {
			
			setStatusBarMessage("Working on Server Certificate");
   		
			p.printServerCertificate();		

		}
	
		if( bCertChainSection ) {
			
			setStatusBarMessage("Working on Server Certificate Chain");

			p.printServerCertificateChain();
		
		}
		
//		if( bServerAnalysisSection ) {
//		
//			setStatusBarMessage("Working on Server Analysis");
//
//			DVPrint.printServerAnalysis();
//		
//		}
	}
	

}
