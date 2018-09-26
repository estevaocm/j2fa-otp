package j2fa.otp;

import java.io.File;
import java.io.FileOutputStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;

import j2fa.qr.QRCode;
import j2fa.utils.ByteUtils;
import j2fa.utils.CryptoUtils;

/**
 * 
 * @author Steven Monteiro
 *
 */
public final class OTPAuthenticationTest {
	
	private OTPAuthenticationTest() {}

	public static void main(String[] args) throws Exception{
		//demo();
		String secret = null;
		secret = generate();
		
		secret = "97AB9B4248BFE25C51BA2EB805BEC41774A8CB3F";
		//qrcode(secret);
		
		verify(secret);
		//TODO Consider previous TOTP code as valid and synchronize with offset as recommended in the RFC.
	}
	
	/*
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
	 */
	private static void demo() {
		// Seed for HMAC-SHA1 - 20 bytes
		String seed = "3132333435363738393031323334353637383930";//hex 40
		// Seed for HMAC-SHA256 - 32 bytes
		String seed32 = seed + "313233343536373839303132";//hex 64
		// Seed for HMAC-SHA512 - 64 bytes
		String seed64 = seed32 + "3334353637383930313233343536373839303132333435363738393031323334";//hex 128
		long T0 = 0;
		long X = 30;
		long testTime[] = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};

		String steps = "0";
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		df.setTimeZone(TimeZone.getTimeZone("UTC"));
		String border = "+---------------+-----------------------+------------------+--------+--------+--------------+";
		try {
			System.out.println(border);
			System.out.println(
					"|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  | Mode   | Microseconds |");
			System.out.println(border);

			for (int i=0; i<testTime.length; i++) {
				long T = (testTime[i] - T0)/X;
				steps = "0000000000000000" + Long.toHexString(T).toUpperCase();
				steps = steps.substring(steps.length() -16);
				String fmtTime = String.format("%1$-11s", testTime[i]);
				String utcTime = df.format(new Date(testTime[i]*1000));
				System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |");
				long t = System.nanoTime();
				String totp = HmacOneTimePassword.generate(seed, steps, "8", HMACAlgorithmEnum.SHA1);
				t = interval(t);
				System.out.println(totp + "| SHA1   | " + t);
				System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |");
				t = System.nanoTime();
				totp = HmacOneTimePassword.generate(seed32, steps, "8", HMACAlgorithmEnum.SHA256);
				t = interval(t);
				System.out.println(totp + "| SHA256 | " + t);
				System.out.print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |");
				t = System.nanoTime();
				totp = HmacOneTimePassword.generate(seed64, steps, "8", HMACAlgorithmEnum.SHA512);
				t = interval(t);
				System.out.println(totp + "| SHA512 | " + t);

				System.out.println(border);
			}
		}catch (Exception e){
			e.printStackTrace();
		}
	}
	
	private static long interval(long start) {
		return (System.nanoTime() -start)/(long)Math.pow(10, 3);//microseconds
	}
	
	private static String generate() throws Exception{
		byte[] randomSeed = CryptoUtils.randomSeed(20);//160 bits key recommended by the HOTP RFC
	    System.out.println("Byte array: " + Arrays.toString(randomSeed) + " (" + randomSeed.length + ")");
	    //[-118, -42, 45, 64, 95, 69, -29, -68, 56, 120, 119, -34, -7, -11, 31, 4, -58, 11, -20, 110]

	    String hex = ByteUtils.bytesToHex(randomSeed);
	    System.out.println("Hexadecimal: " + hex + " (" + hex.length() + ")");
	    //8AD62D405F45E3BC387877DEF9F51F04C60BEC6E (40)
	    
	    String base32 = new Base32().encodeAsString(randomSeed);
	    System.out.println("Base32: " + base32 + " (" + base32.length() + ")");
	    //RLLC2QC7IXR3YODYO7PPT5I7ATDAX3DO (32)
	    
	    String base64 = new Base64().encodeAsString(randomSeed);
	    System.out.println("Base64: " + base64 + " (" + base64.length() + ")");
	    //itYtQF9F47w4eHfe+fUfBMYL7G4= (28)
	    
	    return qrcode(hex);
	}
	
	private static String qrcode(String hex) throws Exception{
	    String path = mockOTPAuth(ByteUtils.hexToBytes(hex)).setupPath(); 
	    System.out.println(path);
	    
		QRCode.generateQRCodeImage(path, 150, 150, new FileOutputStream(new File("qrcode.png")));
		
		return hex;
	}
	
	private static OTPAuthentication mockOTPAuth(byte[] secret) {
		OTPAuthentication o = new OTPAuthentication(secret, "Serpro", "estevaocm@serpro.gov.br", HMACAlgorithmEnum.SHA1, 6, 30);
		return o;
	}
	
	private static void verify(String secret) {
		if(secret == null || secret.isEmpty()) {
			secret = "97AB9B4248BFE25C51BA2EB805BEC41774A8CB3F";
		}
		OTPAuthentication o = mockOTPAuth(ByteUtils.hexToBytes(secret));
		System.out.println("TOTP code: " + o.password());
	}
	
}