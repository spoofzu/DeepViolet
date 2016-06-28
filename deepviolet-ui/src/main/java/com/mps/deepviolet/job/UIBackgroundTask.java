package com.mps.deepviolet.job;

/**
 * A UI background task to do the scanning.
 * @author Milton Smith
 */
public class UIBackgroundTask extends Thread {

	private boolean isworking = false;
	
	private String status = "";
	
	private String largestatus = "";

	
	/**
	 * Override with the code to executive in the background
	 * @throws Exception Thrown on error.
	 */
	protected  void doInBackground() throws Exception {

		// override with template code
		
	}
	
	/**
	 * Return the status bar message to display in the UI for
	 * this background task.
	 * @return String Status message to display.
	 */
	public synchronized String getStatusBarMessage() {
		
		return status;
		
	}
	
	/**
	 * Return the output text from the background task.  For example,
	 * write the results to the UI.
	 * @return String Results of scan task
	 */
	public synchronized String getLargeStatusMessage() {
		
		return largestatus;
		
	}
	
	/**
	 * Mutator method to set the status bar text.
	 * @param status String Message to write.
	 */
	public synchronized void setStatusBarMessage( String status ) {
		
		this.status = status;
		
	}
	
	/**
	 * Mutator method to set the large status message.
	 * @param status String Large status message.
	 */
	public synchronized void setLargeStatusMessage( String status ) {
		
		largestatus = status;
		
	}
	
	/**
	 * Test to see if the background thread is still running.
	 * @return boolean True, thread is still working.  False, thread is finished.
	 */
	public synchronized boolean isWorking() {
		
		return isworking;
		
	}
	
	/**
	 * Mutator method to set the thread work status.
	 * @param isworking True, thread is still working.  False, thread is finished.
	 */
	public synchronized void setWorking( boolean isworking ) {
		
		this.isworking = isworking;
		
	}
	
	/**
	 * Start this thread.
	 */
	public void start() {
		
		setWorking(true); 
		
		super.start();
		//run(); 
	}
	
	/**
	 * Called by thread by framework after start() called by user.
	 */
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
