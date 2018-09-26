package j2fa.utils;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import j2fa.otp.HMACAlgorithm;

public final class CryptoUtils {

	private static final SecureRandom RANDOM = new SecureRandom();
	
	private CryptoUtils() {}
	
	public static byte[] randomSeed(int length) {
		byte[] bytes = new byte[length];
	    RANDOM.nextBytes(bytes);
	    return bytes;
	}

	/**
	 * This method uses the JCE to provide the crypto algorithm.
	 * HMAC computes a Hashed Message Authentication Code with the crypto hash algorithm as a parameter.
	 *
	 * @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
	 * @param keyBytes: the bytes to use for the HMAC key
	 * @param text: the message or text to be authenticated
	 * 
	 * @author Johan Rydell, PortWise, Inc.
	 */
	public static byte[] hmacSha(String crypto, byte[] keyBytes, byte[] text){
		try {
			Mac hmac = Mac.getInstance(crypto);
			SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
			hmac.init(macKey);
			return hmac.doFinal(text);
		} catch (GeneralSecurityException gse) {
			throw new UndeclaredThrowableException(gse);
		}
	}

	/**
	 * This method uses the JCE to provide the HMAC-SHA-1 algorithm. HMAC computes a 
	 * Hashed Message Authentication Code and in this case SHA1 is the hash algorithm used.
	 *
	 * @param keyBytes   the bytes to use for the HMAC-SHA-1 key
	 * @param text       the message or text to be authenticated.
	 *
	 * @throws NoSuchAlgorithmException if no provider makes either HmacSHA1 or HMAC-SHA-1 
	 * 			digest algorithms available.
	 * @throws InvalidKeyException if the secret provided was not a valid HMAC-SHA-1 key.
	 *
	 */
	public static byte[] hmacSha1(byte[] keyBytes, byte[] text){
		try {
			return hmacSha(HMACAlgorithm.SHA1.desc(), keyBytes, text);
		} catch (UndeclaredThrowableException nsae) {
			return hmacSha("HMAC-SHA-1", keyBytes, text);
		}
	}
}
