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
	 * @param key: the shared secret, HEX encoded
	 * @param time: a value that reflects a time
	 * @param returnDigits: number of digits to return
	 * @param crypto: the crypto function to use
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(String key, String time, String returnDigits, String crypto){
		// Using the counter
		// First 8 bytes are for the movingFactor
		// Compliant with base RFC 4226 (HOTP)
		time = "00000000000000000000" + time;
		time = time.substring(time.length() -16);

		// Get the HEX in a Byte[]
		byte[] msg = HexUtils.hexToBytes(time);
		byte[] k = HexUtils.hexToBytes(key);
		byte[] hash = CryptoUtils.hmacSha(crypto, k, msg);

		// put selected bytes into result int
		int offset = offset(hash);

		int codeDigits = Integer.decode(returnDigits);
		int otp = otp(hash, offset, codeDigits);
		
		return formatResult(otp, codeDigits);
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret, HEX encoded
	 * @param time: a value that reflects a time
	 * @param returnDigits: number of digits to return
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */

	public static String generate(String key, String time, String returnDigits){
		return generate(key, time, returnDigits, "HmacSHA1");
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret, HEX encoded
	 * @param time: a value that reflects a time
	 * @param returnDigits: number of digits to return
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */

	public static String generate256(String key, String time, String returnDigits){
		return generate(key, time, returnDigits, "HmacSHA256");
	}
	
	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret, HEX encoded
	 * @param time: a value that reflects a time
	 * @param returnDigits: number of digits to return
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */

	public static String generate512(String key, String time, String returnDigits){
		return generate(key, time, returnDigits, "HmacSHA512");
	}

}