package com.mps.deepviolet.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.Timer;
import javax.swing.border.BevelBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyledDocument;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.mps.deepviolet.job.DeepScanTask;
import com.mps.deepviolet.job.UIBackgroundTask;
import com.mps.deepviolet.util.FileUtils;

/**
 * Build main application UI used by StartUI. Creates the JFrame and deploys
 * user interface control elements.
 * 
 * @author Milton Smith
 *
 */
public class MainFrm extends JFrame {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolet.ui.MainFrm");

	private static final long serialVersionUID = -7591324908851824818L;
	private JTextField txtServer;
	private JTextPane tpResults;
	private StyledDocument doc;
	private JTextField txtStatus;

	JButton btnDeepScan = null;
	JButton btnSave = null;

	private static final String STATUS_HDR = "Status: ";

	URL url = null;

	private static JFileChooser fc;

	/**
	 * CTOR
	 */
	public MainFrm() {

		super();
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		// initComponents();

	}

	/**
	 * Build the UI.
	 */
	public void initComponents() {

		GridBagLayout gbl1 = new GridBagLayout();
		GridBagLayout gbl2 = new GridBagLayout();
		GridBagConstraints c = new GridBagConstraints();
		setLayout(gbl1);

		JPanel pnlMain = new JPanel();
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 1.0;
		c.weighty = 1.0;
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = GridBagConstraints.REMAINDER;
		c.gridheight = GridBagConstraints.REMAINDER;
		add(pnlMain, c);

		pnlMain.setBackground(new Color(240, 240, 240));
		pnlMain.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
		pnlMain.setLayout(gbl2);

		JLabel lblServer = new JLabel("Host(IP)");
		c.fill = GridBagConstraints.HORIZONTAL;
		c.weightx = 0.1;
		c.weighty = 0.1;
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 1;
		c.gridheight = 1;
		pnlMain.add(lblServer, c);

		txtServer = new JTextField("");
		c.fill = GridBagConstraints.HORIZONTAL;
		c.weightx = 1.0;
		c.weighty = 0.1;
		c.gridx = 1;
		c.gridy = 0;
		c.gridwidth = GridBagConstraints.HORIZONTAL;
		c.gridheight = 1;
		pnlMain.add(txtServer, c);

		btnDeepScan = new JButton("Scan");
		c.fill = GridBagConstraints.HORIZONTAL;
		c.weightx = 0.1;
		c.weighty = 0.1;
		c.gridx = 3;
		c.gridy = 0;
		c.gridwidth = 1;
		c.gridheight = 1;
		pnlMain.add(btnDeepScan, c);
		getRootPane().setDefaultButton(btnDeepScan);

		btnSave = new JButton("Save");
		c.fill = GridBagConstraints.HORIZONTAL;
		c.weightx = 0.1;
		c.weighty = 0.1;
		c.gridx = 4;
		c.gridy = 0;
		c.gridwidth = 1;
		c.gridheight = 1;
		pnlMain.add(btnSave, c);

		tpResults = new JTextPane();
		Font font = new Font("Courier New", Font.PLAIN, 12);
		tpResults.setFont(font);

		doc = tpResults.getStyledDocument();
		//
		// // Load the default style and add it as the "regular" text
		// Style def = StyleContext.getDefaultStyleContext().getStyle(
		// StyleContext.DEFAULT_STYLE );
		// Style regular = doc.addStyle( "regular", def );
		//
		// // Create an italic style
		// Style italic = doc.addStyle( "italic", regular );
		// StyleConstants.setItalic( italic, true );
		//
		// // Create a bold style
		// Style sectionhead = doc.addStyle( "sectionhead", regular );
		// StyleConstants.setBold( sectionhead, true );
		//
		// // Create a bold style
		// Style subsectionhead = doc.addStyle( "subsectionhead", regular );
		// StyleConstants.setItalic( subsectionhead, true );
		//
		// // Create a small style
		// Style small = doc.addStyle( "small", regular );
		// StyleConstants.setFontSize( small, 10 );
		//
		// // Create a large style
		// Style large = doc.addStyle( "large", regular );
		// StyleConstants.setFontSize( large, 16 );
		//
		// // Create a highlight style
		// Style highlight = doc.addStyle( "highlight", regular );
		// StyleConstants.setBackground( highlight, Color.yellow );
		//
		// // Create a highlight style
		// Style error = doc.addStyle( "highlight", regular );
		// StyleConstants.setBackground( highlight, Color.red );

		JScrollPane spScrollResults = new JScrollPane(tpResults);
		spScrollResults
				.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		spScrollResults
				.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
		spScrollResults.setBackground(new Color(255, 255, 255));
		// spScrollResults.setBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED));
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 3.0;
		c.weighty = 3.0;
		c.gridx = 0;
		c.gridy = 1;
		c.gridwidth = GridBagConstraints.REMAINDER;
		c.gridwidth = GridBagConstraints.REMAINDER;
		c.anchor = GridBagConstraints.PAGE_END;
		tpResults.setEditable(false);
		pnlMain.add(spScrollResults, c);

		// Status bar at bottom
		txtStatus = new JTextField(STATUS_HDR + "Ready");
		txtStatus.setEditable(false);
		txtStatus.setEnabled(true);
		c.fill = GridBagConstraints.HORIZONTAL;
		c.weightx = 0.1;
		c.weighty = 0.1;
		c.gridx = 0;
		c.gridy = 2;
		c.gridwidth = GridBagConstraints.REMAINDER;
		c.gridheight = 1;
		c.insets = new Insets(5, 5, 10, 5);
		// c.anchor=GridBagConstraints.PAGE_END;
		pnlMain.add(txtStatus, c);

		setSize(800, 800);
		setPreferredSize(new Dimension(800, 800));
		setResizable(true);

		centerOnScreen();
		pack();

		// Listener for Window resize
		this.addComponentListener(new ComponentAdapter() {
			public void componentResized(ComponentEvent e) {
				refresh();
			}
		});

		// Button listener to start the scan.
		btnDeepScan.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				selectionBtnDeepScanPressed();
			}
		});

		// Button listener to save the report results.
		btnSave.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				selectionBtnSavePressed();
			}
		});

	}

	/**
	 * Action when scanned pressed. Basically, setup the background tasks and
	 * execute.
	 */
	private void selectionBtnDeepScanPressed() {

		setEnableControls(false);

		final Style regular = doc.getStyle("regular");
		// final Style sectionhead = doc.getStyle("sectionhead");
		// final Style error = doc.getStyle("error");

		// Basic URL sanitization.
		String surl = txtServer.getText() != null ? txtServer.getText().trim()
				: "";

		try {
			url = new URL(surl);
		} catch (MalformedURLException e) {
			String malformed_url = "Bad host url, err=" + e.getMessage();
			try {
				doc.remove(0, doc.getLength());
				doc.insertString(0, malformed_url, regular);
			} catch (Exception e1) {
				logger.error(e1.getMessage(), e1);
			}
			logger.error(malformed_url);
		}

		if (url == null || !url.getProtocol().toLowerCase().equals("https")) {
			String bad_url = "bad host url, url=" + url;
			try {
				doc.remove(0, doc.getLength());
				doc.insertString(0, bad_url, regular);
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
			logger.error(bad_url);
			setEnableControls(true);
			return;
		}

		try {
			doc.remove(0, doc.getLength());
		} catch (BadLocationException e1) {
			e1.printStackTrace();
		}

		// Background SSL scanning thread
		DeepScanTask st = null;
		try {
			st = new DeepScanTask(url);
		} catch (Exception e) {
			String msg = "";
			if (url.getHost().equals(e.getMessage())) {
				msg = "Host not found or bad URL formatting.  url=" + surl;
			} else {
				msg = "Problem initializing host.  err=" + e.getMessage();
			}
			logger.error(msg);
			try {
				doc.remove(0, doc.getLength());
				doc.insertString(0, msg, regular);
			} catch (Exception e1) {
				logger.error(e1.getMessage(), e);
			}
			setEnableControls(true);
			return;
		}
		st.start();
		// Background UI update thread. Display scan results in progress
		updateLongRunningUIStatus(st);

	}

	/**
	 * Update the status on long running tasks.
	 * 
	 * @param task
	 *            Current task.
	 */
	private void updateLongRunningUIStatus(final UIBackgroundTask task) {

		final Style regular = doc.getStyle("regular");
		// final Style sectionhead = doc.getStyle("sectionhead");
		// final Style error = doc.getStyle("error");

		// Background UI update thread. Display scan results in progress
		int delay = 500; // UI update interval
		ActionListener taskPerformer = new ActionListener() {
			long s1 = System.currentTimeMillis();

			public void actionPerformed(ActionEvent evt) {
				if (task.isWorking()) {
					updateWorkStatus(task.getStatusBarMessage());
					try {

						doc.remove(0, doc.getLength());
						doc.insertString(0, task.getLargeStatusMessage(),
								regular);
					} catch (BadLocationException e) {
						e.printStackTrace();
					}
				} else {
					// Update display before we exit timer.
					long f1 = System.currentTimeMillis();
					try {
						doc.remove(0, doc.getLength());
						doc.insertString(0, task.getLargeStatusMessage(),
								regular);
					} catch (BadLocationException e) {
						e.printStackTrace();
					}
					// Scan done, stop timer.
					((Timer) evt.getSource()).stop();
					updateWorkStatus("Ready, " + (f1 - s1) + "(ms)");
					setEnableControls(true);
				}
			}
		};
		new Timer(delay, taskPerformer).start();

	}

	/**
	 * Action when save button pressed. Save the scan results.
	 */
	private void selectionBtnSavePressed() {

		setEnableControls(false);

		// check to make sure not null and contains at least protocol and host
		if (url == null || url.getHost().length() < 8) {

			logger.warn("Nothing to save.");

		}

		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-z");
		String d = sdf.format(date);

		String h = url.getHost().replace('.', '-');

		// Note, java does not understand tilde (e.g., ~) for the user home. say
		// what?
		String violetdir = FileUtils.getWorkingDirectory();
		violetdir = violetdir + "DeepViolet-" + h + "-" + d + ".txt";
		logger.info("Default DeepViolet report name, name=" + violetdir);

		File default_file = new File(violetdir);

		File currentdirectory = new File(default_file.getPath());
		fc = new JFileChooser();
		fc.setCurrentDirectory(currentdirectory);
		logger.trace(fc.getCurrentDirectory().toString());
		fc.setSelectedFile(default_file);
		logger.trace(fc.getSelectedFile().toString());

		int returnVal = fc.showSaveDialog(this);

		File selectedfile = null;

		if (returnVal == JFileChooser.APPROVE_OPTION) {

			selectedfile = fc.getSelectedFile().getAbsoluteFile();

			logger.info("Saving report results to file.  Name="
					+ selectedfile.getName());

			PrintWriter p = null;
			try {

				selectedfile.createNewFile();

				p = new PrintWriter(selectedfile);

				p.println(tpResults.getText().trim());

			} catch (FileNotFoundException e) {
				logger.error("Unable save scan results.", e);
			} catch (IOException e) {
				logger.debug("Can't create new file.  File="
						+ selectedfile.getAbsolutePath().toString());
			} finally {

				if (p != null) {
					p.flush();
					p.close();
				}
			}

		} else {
			logger.debug("Result save cancelled by user.");
		}

		setEnableControls(true);
	}

	/**
	 * Update UI with a task related work status.
	 * 
	 * @param phase
	 */
	private void updateWorkStatus(String phase) {

		StringBuffer buff = new StringBuffer();

		buff.append(STATUS_HDR);
		buff.append(phase);
		txtStatus.setText(buff.toString());
	}

	/**
	 * Center the UI on the screen.
	 */
	private void centerOnScreen() {

		Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
		this.setLocation(dim.width / 2 - this.getSize().width / 2, dim.height
				/ 2 - this.getSize().height / 2);
	}

	/**
	 * Refresh or update the UI.
	 */
	public void refresh() {

		invalidate();
		revalidate();
		repaint();

	}

	/**
	 * Enable or disable user interface controls. We don't allow the user to
	 * have more than a single scan job running at the moment.
	 * 
	 * @param state
	 *            True, controls are enabled. False, controls are disabled. User
	 *            cannot run new scans.
	 */
	private void setEnableControls(boolean state) {

		btnSave.setEnabled(state);
		btnDeepScan.setEnabled(state);

	}

}
