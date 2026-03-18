package com.mps.deepviolet.persist;

/**
 * Encryption mode for saving {@code .dvscan} scan files.
 *
 * @author Milton Smith
 */
public enum ScanFileMode {

	/**
	 * Plain text JSON — no encryption.
	 * Portable to any machine, but scan data is readable by anyone
	 * with access to the file.
	 */
	PLAIN_TEXT("Plain text"),

	/**
	 * Host locked — encrypted with the machine's auto-generated key.
	 * Zero-friction on the originating machine; the file cannot be
	 * opened on a different machine.
	 */
	HOST_LOCKED("Host locked"),

	/**
	 * Password locked — encrypted with a user-supplied password only.
	 * The password is always required to open the file, even on the
	 * originating machine. The file is portable to any machine.
	 */
	PASSWORD_LOCKED("Password locked");

	private final String displayName;

	ScanFileMode(String displayName) {
		this.displayName = displayName;
	}

	/** Returns the display name.
	 *  @return display name */
	public String getDisplayName() {
		return displayName;
	}
}
