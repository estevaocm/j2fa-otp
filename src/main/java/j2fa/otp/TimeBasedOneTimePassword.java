package j2fa.otp;
/**
 Copyright (c) 2011 IETF Trust and the persons identified as
 authors of the code. All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, is permitted pursuant to, and subject to the license
 terms contained in, the Simplified BSD License set forth in Section
 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents
 (http://trustee.ietf.org/license-info).
 */

import java.math.BigInteger;

/**
 * This is an example implementation of the OATH TOTP algorithm.
 * Visit www.openauthentication.org for more information.
 *
 * @author Johan Rydell, PortWise, Inc.
 * @see https://tools.ietf.org/html/rfc6238
 */

public final class TimeBasedOneTimePassword extends AbstractOneTimePassword {

	private TimeBasedOneTimePassword() {}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret
	 * @param time: a value that reflects a time
	 * @param returnDigits: number of digits to return
	 * @param algo: the crypto function to use
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(byte[] key, byte[] time, int returnDigits, HMACAlgorithm algo){
		byte[] hash = CryptoUtils.hmacSha(algo.desc(), key, time);
		// put selected bytes into result int
		int offset = offset(hash);
		int otp = otp(hash, offset, returnDigits);
		return formatResult(otp, returnDigits);
	}

	public static String generate(byte[] key, long time, int returnDigits, HMACAlgorithm algo){
		return generate(key, ByteUtils.longToBytes(time), returnDigits, algo);
	}
	
	public static String generate(byte[] key, byte[] time){
		return generate(key, time, 6, HMACAlgorithm.SHA1);
	}
	
	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret, HEX encoded
	 * @param time: a value that reflects a time, HEX encoded
	 * @param returnDigits: number of digits to return
	 * @param algo: the crypto function to use
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(String key, String time, String returnDigits, HMACAlgorithm algo){
		return generate(ByteUtils.hexToBytes(key), hex16toBytes(time), Integer.decode(returnDigits), algo);
	}
	
	private static byte[] hex16toBytes(String hex) {
		// Using the counter
		// First 8 bytes are for the movingFactor
		// Compliant with base RFC 4226 (HOTP)
		hex = "00000000000000000000" + hex;
		hex = hex.substring(hex.length() -16);
		// Get the HEX in a Byte[]
		return ByteUtils.hexToBytes(hex);
	}

}