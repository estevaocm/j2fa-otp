package j2fa.otp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @see https://tools.ietf.org/html/rfc4226
 */
public final class HMACBasedOneTimePassword extends AbstractOneTimePassword {
	
	// These are used to calculate the check-sum digits.
	//    0  1  2  3  4  5  6  7  8  9
	private static final int[] DOUBLE_DIGITS = 
		{ 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

	private HMACBasedOneTimePassword() {}

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
	 * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or HMAC-SHA-1 
	 *                     digest algorithms available.
	 * @throws InvalidKeyException if the secret provided was not a valid HMAC-SHA-1 key.
	 *
	 * @return A numeric String in base 10 that includes {@link codeDigits} digits 
	 * plus the optional checksum digit if requested.
	 */
	public static String generate(byte[] secret, long movingFactor, int codeDigits,
			boolean addChecksum, int truncationOffset){
		
		// put movingFactor value into text byte array
		byte[] text = new byte[8];
		for (int i = text.length - 1; i >= 0; i--) {
			text[i] = (byte) (movingFactor & 0xff);
			movingFactor >>= 8;
		}

		// compute hmac hash
		byte[] hash = CryptoUtils.hmacSha1(secret, text);

		// put selected bytes into result int
		int offset = offset(hash);
		if ( (0<=truncationOffset) &&
				(truncationOffset<(hash.length-4)) ) {
			offset = truncationOffset;
		}
		
		int otp = otp(hash, offset, codeDigits);
		if (addChecksum) {
			otp = (otp * 10) + calcChecksum(otp, codeDigits);
		}
		int digits = addChecksum ? (codeDigits + 1) : codeDigits;
		return formatResult(otp, digits);
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