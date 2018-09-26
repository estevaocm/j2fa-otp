package j2fa.otp;

/**
 * @see https://tools.ietf.org/html/rfc4226
 */
public class OneTimePassword {
	
	private static final int[] DIGITS_POWER
		// 0 1  2   3    4     5      6       7        8
		= {1,10,100,1000,10000,100000,1000000,10000000,100000000};
	// These are used to calculate the check-sum digits.
	//    0  1  2  3  4  5  6  7  8  9
	private static final int[] DOUBLE_DIGITS = 
		{ 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret
	 * @param movingFactor: the counter, time, or other value that changes on a per use basis.
	 * @param returnDigits: number of digits to return
	 * @param algo: the crypto function to use
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(byte[] key, byte[] movingFactor, int returnDigits, HMACAlgorithm algo){
		byte[] hash = CryptoUtils.hmacSha(algo.desc(), key, movingFactor);
		// put selected bytes into result int
		int offset = offset(hash);
		int otp = otp(hash, offset, returnDigits);
		return formatResult(otp, returnDigits);
	}

	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret
	 * @param movingFactor: the counter, time, or other value that changes on a per use basis.
	 * @param returnDigits: number of digits to return
	 * @param algo: the crypto function to use
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(byte[] key, long movingFactor, int returnDigits, HMACAlgorithm algo){
		return generate(key, ByteUtils.longToBytes(movingFactor), returnDigits, algo);
	}
	
	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret
	 * @param movingFactor: the counter, time, or other value that changes on a per use basis.
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(byte[] key, byte[] movingFactor){
		return generate(key, movingFactor, 6, HMACAlgorithm.SHA1);
	}
	
	/**
	 * This method generates a TOTP value for the given set of parameters.
	 *
	 * @param key: the shared secret, HEX encoded
	 * @param movingFactor: the counter, time, or other value that changes on a per use basis.
	 * @param returnDigits: number of digits to return
	 * @param algo: the crypto function to use
	 *
	 * @return: a numeric String in base 10 that includes {@link DIGITS_POWER} digits
	 */
	public static String generate(String key, String movingFactor, String returnDigits, HMACAlgorithm algo){
		return generate(ByteUtils.hexToBytes(key), hex16toBytes(movingFactor), Integer.decode(returnDigits), algo);
	}
	
	/**
	 * This method generates an OTP value for the given set of parameters.
	 *
	 * @param secret       the shared secret
	 * @param movingFactor the counter, time, or other value that changes on a per use basis.
	 * @param codeDigits   the number of digits in the OTP, not including the checksum, if any.
	 * @param addChecksum  a flag that indicates if a checksum digit should be appended to the OTP.
	 * @param truncationOffset the offset into the MAC result to begin truncation.  
	 *                     If this value is out of the range of 0 ... 15, then dynamic truncation
	 *                     will be used. Dynamic truncation is when the last 4 bits of the last byte
	 *                     of the MAC are used to determine the start offset.
	 * @return A numeric String in base 10 that includes {@link codeDigits} digits 
	 * plus the optional checksum digit if requested.
	 */
	public static String generate(byte[] secret, byte[] movingFactor, int codeDigits,
			boolean addChecksum, int truncationOffset, HMACAlgorithm algo){
		
		// compute hmac hash
		byte[] hash = CryptoUtils.hmacSha(algo.desc(), secret, movingFactor);

		// put selected bytes into result int
		int offset = offset(hash);
		if ((truncationOffset >= 0)&&(truncationOffset<(hash.length-4))) {
			offset = truncationOffset;
		}
		
		int otp = otp(hash, offset, codeDigits);
		if (addChecksum) {
			otp = (otp * 10) + calcChecksum(otp, codeDigits);
		}
		int digits = addChecksum ? (codeDigits + 1) : codeDigits;
		return formatResult(otp, digits);
	}
	
	public static String generateHOTP(byte[] secret, long movingFactor, int codeDigits,
			boolean addChecksum, int truncationOffset, HMACAlgorithm algo){
		return generate(secret, ByteUtils.longToBytes(movingFactor), codeDigits, 
				addChecksum, truncationOffset, algo);
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

	private static int offset(byte[] hash) {
		return hash[hash.length - 1] & 0xf;
	}
	
	private static int otp(byte[] hash, int offset, int digits) {
		return binary(hash, offset) % DIGITS_POWER[digits];
	}
	
	private static int binary(byte[] hash, int offset) {
		return ((hash[offset] & 0x7f) << 24)
				| ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8)
				| (hash[offset + 3] & 0xff);
	}
	
	private static String formatResult(int otp, int digits) {
		String result = Integer.toString(otp);
		StringBuilder zeros = new StringBuilder();
		while (zeros.length() + result.length() < digits) {
			zeros.append('0');
		}
		return zeros.toString() + result;
	}

	/**
	 * Calculates the checksum using the credit card algorithm. This algorithm has the advantage 
	 * that it detects any single mistyped digit and any single transposition of adjacent digits.
	 *
	 * @param num the number to calculate the checksum for
	 * @param digits number of significant places in the number
	 *
	 * @return the checksum of num
	 */
	public static int calcChecksum(long num, int digits) {
		boolean doubleDigit = true;
		int     total = 0;
		while (0 < digits--) {
			int digit = (int) (num % 10);
			num /= 10;
			if (doubleDigit) {
				digit = DOUBLE_DIGITS[digit];
			}
			total += digit;
			doubleDigit = !doubleDigit;
		}
		int result = total % 10;
		if (result > 0) {
			result = 10 - result;
		}
		return result;
	}

}