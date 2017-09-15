package org.jurr.jsch.bugfix111;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

/**
 * This is a copy of com.jcraft.jsch.jce.SignatureDSA with improvements.
 *
 * It contains:
 * <ul>
 * <li>an improved check for detecting the identification string exchange message</li>
 * <li>a fix for converting from mpint to ASN.1 (fixing <a href="https://sourceforge.net/p/jsch/bugs/111/">bug 111</a>)</li>
 * </ul>
 *
 * @author Jurrie Overgoor &lt;jsch@jurr.org&gt;
 */
public class SignatureDSA implements com.jcraft.jsch.SignatureDSA
{
	private java.security.Signature signature;
	private KeyFactory keyFactory;

	@Override
	public void init() throws Exception
	{
		signature = java.security.Signature.getInstance("SHA1withDSA");
		keyFactory = KeyFactory.getInstance("DSA");
	}

	@Override
	public void setPubKey(final byte[] y, final byte[] p, final byte[] q, final byte[] g) throws Exception
	{
		final DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(new BigInteger(y), new BigInteger(p), new BigInteger(q), new BigInteger(g));
		final PublicKey pubKey = keyFactory.generatePublic(dsaPubKeySpec);
		signature.initVerify(pubKey);
	}

	@Override
	public void setPrvKey(final byte[] x, final byte[] p, final byte[] q, final byte[] g) throws Exception
	{
		final DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(new BigInteger(x), new BigInteger(p), new BigInteger(q), new BigInteger(g));
		final PrivateKey prvKey = keyFactory.generatePrivate(dsaPrivKeySpec);
		signature.initSign(prvKey);
	}

	@Override
	public byte[] sign() throws Exception
	{
		return fromASN1ToMPINT(signature.sign());
	}

	@Override
	public void update(final byte[] foo) throws Exception
	{
		signature.update(foo);
	}

	@Override
	public boolean verify(final byte[] sig) throws Exception
	{
		return signature.verify(fromMPINTtoASN1(sig));
	}

	byte[] fromASN1ToMPINT(final byte[] sig)
	{
		// sig is in ASN.1
		// SEQUENCE::={ r INTEGER, s INTEGER }

		byte[] r = computeMPINT(sig, 3);
		byte[] s = computeMPINT(sig, 4 + r.length + 1);

		byte[] result = new byte[40];

		// result must be 40 bytes, but length of r and s may not be 20 bytes

		System.arraycopy(r, r.length > 20 ? 1 : 0, result, r.length > 20 ? 0 : 20 - r.length, r.length > 20 ? 20 : r.length);
		System.arraycopy(s, s.length > 20 ? 1 : 0, result, s.length > 20 ? 20 : 40 - s.length, s.length > 20 ? 20 : s.length);

		return result;
	}

	private byte[] computeMPINT(final byte[] sig, final int index)
	{
		int len = sig[index] & 0xff;
		byte[] result = new byte[len];
		System.arraycopy(sig, index + 1, result, 0, result.length);
		return result;
	}

	byte[] fromMPINTtoASN1(final byte[] input)
	{
		byte[] sig = input;

		byte[] tmp;

		// 0:0:0:7:73:73:68:2d is the identification string exchange message
		if (sig[0] == 0 && sig[1] == 0 && sig[2] == 0 && sig[3] == 0x07 && sig[4] == 0x73 && sig[5] == 0x73 && sig[6] == 0x68 && sig[7] == 0x2d)
		{
			int i = 0;
			int j = 0;
			j = sig[i++] << 24 & 0xff000000 | sig[i++] << 16 & 0x00ff0000 | sig[i++] << 8 & 0x0000ff00 | sig[i++] & 0x000000ff;
			i += j;
			j = sig[i++] << 24 & 0xff000000 | sig[i++] << 16 & 0x00ff0000 | sig[i++] << 8 & 0x0000ff00 | sig[i++] & 0x000000ff;
			tmp = new byte[j];
			System.arraycopy(sig, i, tmp, 0, j);
			sig = tmp;
		}

		int[] lengthsFirst = computeASN1Length(sig, 0);
		int[] lengthsSecond = computeASN1Length(sig, 20);

		int lengthOfFrst = lengthsFirst[0];
		int lengthOfScnd = lengthsSecond[0];
		int lengthOfFrstMax20 = lengthsFirst[1];
		int lengthOfScndMax20 = lengthsSecond[1];

		int length = 6 + lengthOfFrst + lengthOfScnd;
		tmp = new byte[length];
		tmp[0] = (byte) 0x30; // ASN.1 SEQUENCE
		tmp[1] = (byte) (lengthOfFrst + lengthOfScnd + 4); // ASN.1 length of sequence
		tmp[2] = (byte) 0x02; // ASN.1 INTEGER
		tmp[3] = (byte) lengthOfFrst; // ASN.1 length of integer
		System.arraycopy(sig, 20 - lengthOfFrstMax20, tmp, 4 + (lengthOfFrst > 20 ? 1 : 0), lengthOfFrstMax20);
		tmp[4 + tmp[3]] = (byte) 0x02; // ASN.1 INTEGER
		tmp[5 + tmp[3]] = (byte) lengthOfScnd; // ASN.1 length of integer
		System.arraycopy(sig, 20 + 20 - lengthOfScndMax20, tmp, 6 + tmp[3] + (lengthOfScnd > 20 ? 1 : 0), lengthOfScndMax20);
		sig = tmp;

		return sig;
	}

	private int[] computeASN1Length(final byte[] sig, final int index)
	{
		int maxLength = 20;
		int length = 20;
		if ((sig[index] & 0x80) != 0)
		{
			// ASN.1 would see this as negative INTEGER, so we add a leading 0x00 byte.
			length++;
		}
		else
		{
			while (sig[index + 20 - length] == 0 && (sig[index + 20 - length + 1] & 0x80) != 0x80)
			{
				// The mpint starts with redundant 0x00 bytes.
				length--;
			}
			maxLength = length;
		}
		return new int[] { length, maxLength };
	}
}