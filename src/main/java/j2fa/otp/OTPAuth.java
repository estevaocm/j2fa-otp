package j2fa.otp;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base32;

public class OTPAuth {
	
	private String type = "totp";//TODO hotp
	private String issuer;
	private String account;
	private byte[] secret; 
	private String secretBase32; 
	private HMACAlgorithm algo;
	private Integer digits;
	private Integer period;
	private Integer counter;//REQUIRED if type is hotp: The counter parameter is required when provisioning a key for use with HOTP. It will set the initial counter value.
	
	/**
	 * 
	 * @param secretHex Secret key.
	 * @param issuer Issuer of the code and account.
	 * @param account User account. Typically the user's e-mail address.
	 * @param algo OTP hash algorithm: SHA1 (default), SHA256, or SHA512.  
	 * @param digits Number of digits in the code. Recommended: 6 or 8.
	 * @param period TOTP code validity period in seconds. Recommended: 30 seconds.
	 */
	public OTPAuth(byte[] secret, String issuer, String account,  
			HMACAlgorithm algo, Integer digits, Integer period) {
		if(secret == null || secret.length == 0) {
			throw new IllegalArgumentException("secret");
		}
		this.secret = secret;
		this.algo = algo;
		this.digits = digits;
		this.period = period;
		this.secretBase32 = new Base32().encodeAsString(secret);
		this.issuer = issuer;
		this.account = account;
	}
	
	/**
	 * 
	 * @return OTPAuth path for setting up the client. Usually presented as a QR code.
	 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	 */
	public String setupPath() {
		//TODO URL encode
		List<String> errors = new ArrayList<String>();
		if(this.issuer == null || this.issuer.isEmpty()) {
			errors.add(this.issuer);
		}
		if(this.account == null || this.account.isEmpty()) {
			errors.add(this.account);
		}
		if(!errors.isEmpty()) {
			throw new IllegalStateException("Data missing: " + errors);
		}
		String path = "otpauth://" + this.type + "/" + this.issuer + ":" + this.account 
				+ "?secret=" + this.secretBase32 + "&issuer=" + this.issuer;
		if(this.algo != null) {//default: SHA1
			path += "&algorithm=" + this.algo.desc();
		}
		if(this.digits != null) {//default: 6
			path += "&digits=" + this.digits;
		}
		if(this.period != null) {//default: 30
			path += "&period=" + this.period;
		}
	    return path;
	}
	
	public String setupPath(String issuer, String account) {
		this.issuer = issuer;
		this.account = account;
		return setupPath();
	}
	
	/**
	 * 
	 * @return The TOTP code for the current Unix time.
	 */
	public String generate() {
		return generate(System.currentTimeMillis());
	}

	/**
	 * 
	 * @param unixTime
	 * @return The TOTP code for the given Unix time.
	 */
	public String generate(long unixTime) {
		long time = (unixTime/1000L)/this.period;
		int digits = 6;
		if(this.digits != null) {
			digits = this.digits;
		}
		return OneTimePassword.generate(this.secret, time, digits, HMACAlgorithm.SHA1);
	}

	/**
	 * Generates the TOTP code for the given Unix time adjusted by the given number of steps of the period
	 * parameter. This may be necessary to account for network latency or clock synchronization. 
	 * The RFC recommends the steps to be no larger than 1.0 and no smaller than -1.0, in the case of latency.
	 * For synchronization, the adjustment could be larger but should be recorded and fixed.
	 * @param unixTime
	 * @param step 
	 * @return 
	 * @see Sections 5.2 and 6 of https://tools.ietf.org/html/rfc6238
	 */
	public String generate(long unixTime, double step) {
		return generate(unixTime + (int)(step * this.period));
	}
}