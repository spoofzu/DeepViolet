package com.mps.deepviolet.api;

import java.net.UnknownHostException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A background task to do the scanning.
 * Subclass and override {@link #doInBackground()} to provide scan logic.
 * @author Milton Smith
 */
public class BackgroundTask extends Thread {

	/** Creates a new background task. */
	public BackgroundTask() {}

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.BackgroundTask");

	private boolean isworking = false;
	
	private String status = "";
	
	private String largestatus = "";

	
	/**
	 * Override with the code to execute in the background
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

	private volatile boolean cancelled;
	private volatile boolean paused;
	private final Object pauseLock = new Object();

	/**
	 * Request cooperative cancellation of this background task.
	 * Scan methods check {@link #isCancelled()} at natural boundaries and bail out.
	 * Also wakes any thread blocked in {@link #waitIfPaused()}.
	 */
	public void cancel() {
		this.cancelled = true;
		synchronized (pauseLock) {
			pauseLock.notifyAll();
		}
	}

	/**
	 * Check whether this task has been cancelled.
	 * @return true if {@link #cancel()} has been called
	 */
	public boolean isCancelled() { return cancelled; }

	/**
	 * Request cooperative pause of this background task.
	 * The scanning thread will block at the next call to {@link #waitIfPaused()}.
	 */
	public void pause() {
		synchronized (pauseLock) {
			this.paused = true;
		}
	}

	/**
	 * Resume a paused background task.
	 * Wakes any thread blocked in {@link #waitIfPaused()}.
	 */
	public void unpause() {
		synchronized (pauseLock) {
			this.paused = false;
			pauseLock.notifyAll();
		}
	}

	/**
	 * Check whether this task has been paused.
	 * @return true if {@link #pause()} has been called and {@link #resume()} has not
	 */
	public boolean isPaused()    { return paused; }

	/**
	 * Block the calling thread while this task is paused.
	 * Returns immediately if not paused. Also returns if
	 * {@link #cancel()} is called while paused, or if the thread is interrupted.
	 */
	public void waitIfPaused() {
		synchronized (pauseLock) {
			while (paused && !cancelled) {
				try {
					pauseLock.wait();
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					break;
				}
			}
		}
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
		} catch( UnknownHostException e ) {
				setLargeStatusMessage("Bad host name.  msg="+e.getMessage());
		} catch (Exception e) {
			setLargeStatusMessage("Error occurred: "+e.getMessage());
			logger.error("Background task failed", e);
		} finally {
			setWorking(false);
		}
     }
}
