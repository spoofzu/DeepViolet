package com.mps.deepviolet.api;

/**
 * Offline features available.  Specifically offline features
 * are those that do not require an inialized host
 * @author Milton Smith
 * @see <a href="DVFactory.html#initializeSession(URL)">DVFactory.initializeSession(URL)</a>
 */
public interface IDVOffEng {

	/**
	 * Return the Major Version of DeepViolet.  Incremented upon significant
	 * addition of new features.  Existing features could also break code.
	 * Callers are urged to test upon implementing new major versions.
	 * @return Number indicating DeepVioloet Major Version.
	 */
	public int getDeepVioletMajorVersion();

	/**
	 * Return the Minor Version of DeepViolet.  Incrememented upon significant
	 * improvement to existing features.   Callers are urged to test upon
	 * implementing new major versions.
	 * @return Number indicating DeepVioloet Minor Version.
	 */
	public int getDeepVioletMinorVersion();

	/**
	 * Return the Build Version of DeepViolet.  Incremented on bug fixes to
	 * existing features.  It's not anticiapted this any improvemnets will
	 * break code.  Callers are urged to perform basic unit tests.
	 * @return Number indicating DeepVioloet Build Version.
	 */
	public int getDeepVioletBuildVersion();

	/**
	 * Return the DeepViolet version string.  
	 * @return Suitable for printing in log files, displaying in About boxes, etc.
	 */
	public String getDeepVioletStringVersion();
	
	/**
     * Return offline print engine instance.  Useful for reporting
     * featurees that don't require initializing an online host.
     * For example, printing PEM encoded X.509 certificates.
	 * @return Offline print engine instance
	 * @throws DVException on problems.
	 */
	public IDVOffPrint getDVOffPrint() throws DVException;
	
}
