package org.jurr.jsch.bugfix111;

import com.jcraft.jsch.JSch;

/**
 * This is an alternative implementation of SignatureDSA and SignatureRSA from JSCH with improvements.
 *
 * It contains:
 * <ul>
 * <li>an improved check for detecting the identification string exchange message</li>
 * <li>a fix for converting from mpint to ASN.1 (fixing <a href="https://sourceforge.net/p/jsch/bugs/111/">bug 111</a>)</li>
 * </ul>
 *
 * @author Jurrie Overgoor &lt;jsch@jurr.org&gt;
 */
public final class JSCH111BugFix
{
	private JSCH111BugFix()
	{
	}

	public static void init()
	{
		JSch.setConfig("signature.dss", SignatureDSA.class.getCanonicalName());
		JSch.setConfig("signature.rsa", SignatureRSA.class.getCanonicalName());
	}
}