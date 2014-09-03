package com.mps.deepviolet.job;

import java.net.URL;

import com.mps.deepviolet.ui.DocPrintUtil;

public class DeepScanTask extends UIBackgroundTask {

	protected volatile StringBuffer con = new StringBuffer();	
	
	private URL url;
	
	public DeepScanTask( URL url ) {
		
		this.url = url;
		
	}
	
	
	public String getLargeStatusMessage() {
		
		return con.toString();
		
	}
	
	protected  void doInBackground() throws Exception {

		
		setStatusBarMessage("Working on Report Header");
   
		DocPrintUtil.printReportHeader(con,url);
   
		

		setStatusBarMessage("Working on Host Information");
   		
		DocPrintUtil.printHostInformation(con, url);
   

		
		setStatusBarMessage("Working on Connection Characteristics");

		DocPrintUtil.printConnectionCharacteristics(con, url);
	
    
		setStatusBarMessage("Working on Supported Cipher Suites");
   
		DocPrintUtil.printSupportedCipherSuites(con, url);
	
	  
   
		setStatusBarMessage("Working on Server Certificate");
   
		DocPrintUtil.printServerCertificate(con, url);

 	
	
		setStatusBarMessage("Working on Server Certificate Chain");

		DocPrintUtil.printServerCertificateChain(con, url);
		
	}
	

}
