package j2fa.utils;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * 
 * @author Steven Monteiro
 *
 */
public final class ByteUtils {
	
	private static final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
	
	private ByteUtils() {}
	
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
	
	public static byte[] longToBytes(long l) {
	    byte[] result = new byte[Long.BYTES];
	    for (int i = result.length -1; i >= 0; i--) {
	        result[i] = (byte)(l & 0xFF);
	        l >>= 8;
	    }
	    return result;
	}	
	
}
