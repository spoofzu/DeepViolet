package com.mps.deepviolet.job;


public class UIBackgroundTask extends Thread {

	private boolean isworking = false;
	
	private String status = "";
	
	private String largestatus = "";

	protected  void doInBackground() throws Exception {

		// override with template code
		
	}
	
	public synchronized String getStatusBarMessage() {
		
		return status;
		
	}
	
	public synchronized String getLargeStatusMessage() {
		
		return largestatus;
		
	}
	
	public synchronized void setStatusBarMessage( String status ) {
		
		this.status = status;
		
	}
	
	public synchronized void setLargeStatusMessage( String status ) {
		
		largestatus = status;
		
	}
	
	public synchronized boolean isWorking() {
		
		return isworking;
		
	}
	
	public synchronized void setWorking( boolean isworking ) {
		
		this.isworking = isworking;
		
	}
	
	public void start() {
		
		setWorking(true); 
		
		super.start();
		//run(); 
	}
	
	public void run() {

		 try {
			doInBackground();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			setWorking(false);
		}
     }
}
