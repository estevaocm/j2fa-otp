package j2fa.otp;

public class AbstractOneTimePassword {
	
	protected static final int[] DIGITS_POWER
		// 0 1  2   3    4     5      6       7        8
		= {1,10,100,1000,10000,100000,1000000,10000000,100000000};

	protected static int offset(byte[] hash) {
		return hash[hash.length - 1] & 0xf;
	}
	
	protected static int otp(byte[] hash, int offset, int digits) {
		return binary(hash, offset) % DIGITS_POWER[digits];
	}
	
	private static int binary(byte[] hash, int offset) {
		return ((hash[offset] & 0x7f) << 24)
				| ((hash[offset + 1] & 0xff) << 16)
				| ((hash[offset + 2] & 0xff) << 8)
				| (hash[offset + 3] & 0xff);
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