package j2fa.otp;

import java.math.BigInteger;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base32;

public final class DataUtils {
	
	private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
	
	private DataUtils() {}
	
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for(int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_CHARS[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_CHARS[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	public static byte[] hexToBytes(String hex){
		// Adding one byte to get the right conversion
		// Values starting with "0" can be converted
		byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
		// Copy all the REAL bytes, not the "first"
		return Arrays.copyOfRange(bArray, 1, bArray.length);
	}
	
}
