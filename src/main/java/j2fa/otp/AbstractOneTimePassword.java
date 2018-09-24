/*
 * OneTimePasswordAlgorithm.java
 * OATH Initiative,
 * HOTP one-time password algorithm
 *
 */

/* Copyright (C) 2004, OATH.  All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "OATH HOTP Algorithm" in all material
 * mentioning or referencing this software or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as
 *  "derived from OATH HOTP algorithm"
 * in all material mentioning or referencing the derived work.
 *
 * OATH (Open AuTHentication) and its members make no
 * representations concerning either the merchantability of this
 * software or the suitability of this software for any particular
 * purpose.
 *
 * It is provided "as is" without express or implied warranty
 * of any kind and OATH AND ITS MEMBERS EXPRESSaLY DISCLAIMS
 * ANY WARRANTY OR LIABILITY OF ANY KIND relating to this software.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

package j2fa.otp;

/**
 * This class contains static methods that are used to calculate the
 * One-Time Password (OTP) using JCE to provide the HMAC-SHA-1.
 *
 * @author Loren Hart
 * @see https://tools.ietf.org/html/rfc4226
 */
public class AbstractOneTimePassword {
	
	protected static final int[] DIGITS_POWER
		// 0 1  2   3    4     5      6       7        8
		= {1,10,100,1000,10000,100000,1000000,10000000,100000000};

	protected static int offset(byte[] hash) {
		return hash[hash.length - 1] & 0xf;
	}
	
	protected static int binary(byte[] hash, int offset) {
		return ((hash[offset] & 0x7f) << 24)
				| ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8)
				| (hash[offset + 3] & 0xff);
	}
	
	protected static int otp(byte[] hash, int offset, int digits) {
		return binary(hash, offset) % DIGITS_POWER[digits];
	}
	
	protected static String formatResult(int otp, int digits) {
		String result = Integer.toString(otp);
		StringBuilder zeros = new StringBuilder();
		while (zeros.length() + result.length() < digits) {
			zeros.append('0');
		}
		return zeros.toString() + result;
	}
}