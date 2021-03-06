package org.jurr.jsch.bugfix111;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.jcraft.jsch.jce.KeyPairGenDSA;
import org.junit.Ignore;
import org.junit.Test;

public class SignatureDSATest
{
	@Test
	@Ignore("Because of the eternal loop, this test will never finish")
	public void testGenKeypair() throws Exception
	{
		// The hash is different every time because of a random variable k.
		while (true)
		{
			final KeyPairGenDSA keypairgen = new KeyPairGenDSA();
			keypairgen.init(1024);
			byte[] p = keypairgen.getP();
			byte[] q = keypairgen.getQ();
			byte[] g = keypairgen.getG();
			byte[] y = keypairgen.getY(); // Public
			byte[] x = keypairgen.getX(); // Private

			byte[] H = new byte[] { -4, 111, -103, 111, 72, -106, 105, -19, 81, -123, 84, -13, -40, -53, -3, -97, -8, 43, -22, -2, -23, -15, 28, 116, -63, 96, -79, -127, -84, 63, -6, -94 };

			final SignatureDSA signatureDSAForSigning = new SignatureDSA();
			signatureDSAForSigning.init();
			signatureDSAForSigning.setPrvKey(x, p, q, g);
			signatureDSAForSigning.update(H);
			byte[] sig_of_H = signatureDSAForSigning.sign();

			final SignatureDSA signatureDSAForVerifying = new SignatureDSA();
			signatureDSAForVerifying.init();
			signatureDSAForVerifying.setPubKey(y, p, q, g);
			signatureDSAForVerifying.update(H);
			boolean verified = signatureDSAForVerifying.verify(sig_of_H);

			System.out.print("sig_of_H[" + sig_of_H.length + "] ");
			for (byte element : sig_of_H)
			{
				final int byteValue = element & 0xff;
				if (byteValue <= 0x0f)
				{
					// Make nice columns
					System.out.print('0');
				}
				System.out.print(Integer.toHexString(byteValue) + ":");
			}
			System.out.println("");

			assertTrue(verified);
		}
	}

	@Test
	public void testImprovedIdentificationStringExchangeMessageDetection()
	{
		final byte[] asn1 = new byte[] { 0x30, 0x2a, 0x2, 0x12, 0x0, 0x0, 0x0, (byte) 0xc8, 0x48, (byte) 0xb7, (byte) 0xb2, 0x61, (byte) 0x96, (byte) 0xe1, 0xb, 0x15, (byte) 0xf0, 0x7e, (byte) 0xac, 0x69, 0x4, 0xf, 0x2, 0x14, 0x6a, (byte) 0xbd, (byte) 0xd6, (byte) 0xe3, (byte) 0xf6, (byte) 0xba, (byte) 0xe7, (byte) 0xba, (byte) 0xd6, 0x6c, 0x2c, (byte) 0xc8, 0x53, (byte) 0x89, 0x7c, (byte) 0xe9, (byte) 0x9b, (byte) 0xb4, (byte) 0xfc, 0x9 };

		final SignatureDSA signature = new SignatureDSA();
		final byte[] fromASN1 = signature.fromASN1ToMPINT(asn1);

		final byte[] toASN1 = signature.fromMPINTtoASN1(fromASN1);
		assertFalse(Arrays.equals(asn1, toASN1));
	}

	@Test
	public void testConversionToFromASN1()
	{
		final List<byte[]> tests = new ArrayList<>();
		// Normal tests
		tests.add(new byte[] { 0x30, 0x2c, 0x2, 0x14, 0x0, (byte) 0xff, (byte) 0xa2, 0x4b, (byte) 0xe3, 0xd, 0x62, 0x6f, 0x69, 0x3a, 0x1f, 0x17, (byte) 0xeb, (byte) 0xc8, (byte) 0xe0, (byte) 0xcb, 0x2, 0x68, (byte) 0xc9, 0x74, 0x2, 0x14, 0x3a, (byte) 0xeb, 0x3d, (byte) 0xb7, 0x34, 0xf, 0x53, (byte) 0x89, 0x50, 0x36, (byte) 0x8e, 0x34, 0x34, (byte) 0xc2, (byte) 0x8c, 0x6a, 0x37, (byte) 0xb7, 0x45, 0x3d });
		tests.add(new byte[] { 0x30, 0x2c, 0x2, 0x14, 0x0, (byte) 0xff, (byte) 0xcc, 0x6, (byte) 0xc4, (byte) 0xf4, (byte) 0x93, (byte) 0xe8, 0x3c, (byte) 0xc1, (byte) 0xef, 0x1f, 0x61, (byte) 0xa1, (byte) 0xba, 0x5a, 0x29, (byte) 0xcb, 0x2a, (byte) 0x95, 0x2, 0x14, 0x8, (byte) 0xb2, 0x50, 0x1c, (byte) 0xac, 0x59, (byte) 0xc7, (byte) 0xec, 0x3c, (byte) 0xcb, (byte) 0xf6, (byte) 0xd7, 0x63, 0x21, 0x72, (byte) 0xfd, (byte) 0xa2, (byte) 0x86, 0x2, 0x3d });

		// Test for the 0x80 mask check
		tests.add(new byte[] { 0x30, 0x2a, 0x2, 0x12, 0x0, (byte) 0x9c, (byte) 0xdb, (byte) 0xc8, 0x48, (byte) 0xb7, (byte) 0xb2, 0x61, (byte) 0x96, (byte) 0xe1, 0xb, 0x15, (byte) 0xf0, 0x7e, (byte) 0xac, 0x69, 0x4, 0xf, 0x2, 0x14, 0x6a, (byte) 0xbd, (byte) 0xd6, (byte) 0xe3, (byte) 0xf6, (byte) 0xba, (byte) 0xe7, (byte) 0xba, (byte) 0xd6, 0x6c, 0x2c, (byte) 0xc8, 0x53, (byte) 0x89, 0x7c, (byte) 0xe9, (byte) 0x9b, (byte) 0xb4, (byte) 0xfc, 0x9 });

		for (final byte[] asn1 : tests)
		{
			final SignatureDSA signature = new SignatureDSA();
			final byte[] fromASN1 = signature.fromASN1ToMPINT(asn1);
			final byte[] toASN1 = signature.fromMPINTtoASN1(fromASN1);
			assertArrayEquals("Conversion ASN.1 -> mpint -> ASN.1 failed", asn1, toASN1);
		}
	}

	@Test
	public void testNormalSignature() throws Exception
	{
		final SignatureDSA signatureDSA = new SignatureDSA();
		signatureDSA.init();

		byte[] y = new byte[] { 103, 23, -102, -4, -110, -90, 66, -52, -14, 125, -16, -76, -110, 33, -111, -113, -46, 27, -118, -73, 0, -19, -48, 43, -102, 56, -49, -84, 118, -10, 76, 84, -5, 84, 55, 72, -115, -34, 95, 80, 32, -120, 57, 101, -64, 111, -37, -26, 96, 55, -98, -24, -99, -81, 60, 22, 5, -55, 119, -95, -28, 114, -40, 13, 97, 65, 22, 33, 117, -59, 22, 81, -56, 98, -112, 103, -62, 90, -12, 81, 61, -67, 104, -24, 67, -18, -60, 78, -127, 44, 13, 11, -117, -118, -69, 89, -25, 26, 103, 72, -83, 114, -40, -124, -10, -31, -34, -49, -54, -15, 92, 79, -40, 14, -12, 58, -112, -30, 11, 48, 26, 121, 105, -68, 92, -93, 99, -78 };
		byte[] p = new byte[] { 0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57 };
		byte[] q = new byte[] { 0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11 };
		byte[] g = new byte[] { 0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42 };
		signatureDSA.setPubKey(y, p, q, g);

		byte[] H = new byte[] { -13, 20, 103, 73, 115, -68, 113, 74, -25, 12, -90, 19, 56, 73, -7, -49, -118, 107, -69, -39, -6, 82, -123, 54, -10, -43, 16, -117, -59, 36, -49, 27 };
		signatureDSA.update(H);

		byte[] sig_of_H = new byte[] { 0, 0, 0, 7, 115, 115, 104, 45, 100, 115, 115, 0, 0, 0, 40, -113, -52, 88, -117, 80, -105, -92, -124, -49, 56, -35, 90, -9, -128, 31, -33, -18, 13, -5, 7, 108, -2, 92, 108, 85, 58, 39, 99, 122, -118, 125, -121, 21, -37, 2, 55, 109, -23, -125, 4 };
		boolean verified = signatureDSA.verify(sig_of_H);

		assertTrue(verified);
	}

	@Test
	public void testTooShortSignature() throws Exception
	{
		final SignatureDSA signatureDSA = new SignatureDSA();
		signatureDSA.init();

		byte[] y = new byte[] { 0, -92, 59, 5, 72, 124, 101, 124, -18, 114, 7, 100, 98, -61, 73, -104, 120, -98, 54, 118, 17, -62, 91, -110, 29, 98, 50, -101, -41, 99, -116, 101, 107, -123, 124, -97, 62, 119, 88, -109, -110, -1, 109, 119, -51, 69, -98, -105, 2, -69, -121, -82, -118, 23, -6, 96, -61, -65, 102, -58, -74, 32, -104, 116, -6, -35, -83, -10, -88, -68, 106, -112, 72, -2, 35, 38, 15, -11, -22, 30, -114, -46, -47, -18, -17, -71, 24, -25, 28, 13, 29, -40, 101, 18, 81, 45, -120, -67, -53, -41, 11, 50, -89, -33, 50, 54, -14, -91, -35, 12, -42, 13, -84, -19, 100, -3, -85, -18, 74, 99, -49, 64, -49, 51, -83, -82, -127, 116, 64 };
		byte[] p = new byte[] { 0, -3, 127, 83, -127, 29, 117, 18, 41, 82, -33, 74, -100, 46, -20, -28, -25, -10, 17, -73, 82, 60, -17, 68, 0, -61, 30, 63, -128, -74, 81, 38, 105, 69, 93, 64, 34, 81, -5, 89, 61, -115, 88, -6, -65, -59, -11, -70, 48, -10, -53, -101, 85, 108, -41, -127, 59, -128, 29, 52, 111, -14, 102, 96, -73, 107, -103, 80, -91, -92, -97, -97, -24, 4, 123, 16, 34, -62, 79, -69, -87, -41, -2, -73, -58, 27, -8, 59, 87, -25, -58, -88, -90, 21, 15, 4, -5, -125, -10, -45, -59, 30, -61, 2, 53, 84, 19, 90, 22, -111, 50, -10, 117, -13, -82, 43, 97, -41, 42, -17, -14, 34, 3, 25, -99, -47, 72, 1, -57 };
		byte[] q = new byte[] { 0, -105, 96, 80, -113, 21, 35, 11, -52, -78, -110, -71, -126, -94, -21, -124, 11, -16, 88, 28, -11 };
		byte[] g = new byte[] { 0, -9, -31, -96, -123, -42, -101, 61, -34, -53, -68, -85, 92, 54, -72, 87, -71, 121, -108, -81, -69, -6, 58, -22, -126, -7, 87, 76, 11, 61, 7, -126, 103, 81, 89, 87, -114, -70, -44, 89, 79, -26, 113, 7, 16, -127, -128, -76, 73, 22, 113, 35, -24, 76, 40, 22, 19, -73, -49, 9, 50, -116, -56, -90, -31, 60, 22, 122, -117, 84, 124, -115, 40, -32, -93, -82, 30, 43, -77, -90, 117, -111, 110, -93, 127, 11, -6, 33, 53, 98, -15, -5, 98, 122, 1, 36, 59, -52, -92, -15, -66, -88, 81, -112, -119, -88, -125, -33, -31, 90, -27, -97, 6, -110, -117, 102, 94, -128, 123, 85, 37, 100, 1, 76, 59, -2, -49, 73, 42 };
		signatureDSA.setPubKey(y, p, q, g);

		byte[] H = new byte[] { -4, 111, -103, 111, 72, -106, 105, -19, 81, -123, 84, -13, -40, -53, -3, -97, -8, 43, -22, -2, -23, -15, 28, 116, -63, 96, -79, -127, -84, 63, -6, -94 };
		signatureDSA.update(H);

		byte[] sig_of_H = new byte[] { 0, 0, 0, 7, 115, 115, 104, 45, 100, 115, 115, 0, 0, 0, 40, 0, 79, 84, 118, -50, 11, -117, -112, 52, -25, -78, -50, -20, 6, -69, -26, 7, 90, -34, -124, 80, 76, -32, -23, -8, 43, 38, -48, -89, -17, -60, -1, -78, 112, -88, 14, -39, -78, -98, -80 };
		boolean verified = signatureDSA.verify(sig_of_H);

		assertTrue(verified);
	}
}