package org.jurr.jsch.bugfix111;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * This is a copy of com.jcraft.jsch.jce.SignatureRSA with improvements.
 *
 * It contains:
 * <ul>
 * <li>improved check for detecting the identification string exchange message</li>
 * </ul>
 *
 * @author Jurrie Overgoor &lt;jsch@jurr.org&gt;
 */
public class SignatureRSA implements com.jcraft.jsch.SignatureRSA
{
	private java.security.Signature signature;
	private KeyFactory keyFactory;

	@Override
	public void init() throws Exception
	{
		signature = java.security.Signature.getInstance("SHA1withRSA");
		keyFactory = KeyFactory.getInstance("RSA");
	}

	@Override
	public void setPubKey(final byte[] e, final byte[] n) throws Exception
	{
		final RSAPublicKeySpec rsaPubKeySpec = new RSAPublicKeySpec(new BigInteger(n), new BigInteger(e));
		final PublicKey pubKey = keyFactory.generatePublic(rsaPubKeySpec);
		signature.initVerify(pubKey);
	}

	@Override
	public void setPrvKey(final byte[] d, final byte[] n) throws Exception
	{
		final RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(new BigInteger(n), new BigInteger(d));
		final PrivateKey prvKey = keyFactory.generatePrivate(rsaPrivKeySpec);
		signature.initSign(prvKey);
	}

	@Override
	public byte[] sign() throws Exception
	{
		return signature.sign();
	}

	@Override
	public void update(final byte[] foo) throws Exception
	{
		signature.update(foo);
	}

	@Override
	public boolean verify(final byte[] sig) throws Exception
	{
		// 0:0:0:7:73:73:68:2d is the identification string exchange message
		if (sig[0] == 0 && sig[1] == 0 && sig[2] == 0 && sig[3] == 0x07 && sig[4] == 0x73 && sig[5] == 0x73 && sig[6] == 0x68 && sig[7] == 0x2d)
		{
			int i = 0, j = 0;
			byte[] tmp;
			j = sig[i++] << 24 & 0xff000000 | sig[i++] << 16 & 0x00ff0000 | sig[i++] << 8 & 0x0000ff00 | sig[i++] & 0x000000ff;
			i += j;
			j = sig[i++] << 24 & 0xff000000 | sig[i++] << 16 & 0x00ff0000 | sig[i++] << 8 & 0x0000ff00 | sig[i++] & 0x000000ff;
			tmp = new byte[j];
			System.arraycopy(sig, i, tmp, 0, j);
			return signature.verify(tmp);
		}
		else
		{
			return signature.verify(sig);
		}
	}
}