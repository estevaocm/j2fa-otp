package j2fa.otp;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base32;

/**
 * 
 * @author Steven Monteiro
 *
 */
public class OTPAuthentication {
	
	private String type;
	private String issuer;
	private String account;
	private byte[] secret; 
	private String secretBase32; 
	private HMACAlgorithmEnum algo;
	private Integer digits;
	private Integer period;
	private Long counter; 
	
	/**
	 * Constructor for TOTP.
	 * @param secret Secret key.
	 * @param issuer Issuer of the code and account.
	 * @param account User account. Typically the user's e-mail address.
	 * @param algo OTP hash algorithm: SHA1 (default), SHA256, or SHA512.  
	 * @param digits Number of digits in the code. Recommended: 6 or 8.
	 * @param period TOTP code validity period in seconds. Recommended: 30 seconds. 
	 * 		Required when provisioning a key for use with TOTP.
	 */
	public OTPAuthentication(byte[] secret, String issuer, String account,  
			HMACAlgorithmEnum algo, Integer digits, Integer period) {
		this(secret, issuer, account, algo, digits, period, null);
	}
	
	/**
	 * Constructor for HOTP.
	 * @param secret Secret key.
	 * @param issuer Issuer of the code and account.
	 * @param account User account. Typically the user's e-mail address.
	 * @param algo OTP hash algorithm: SHA1 (default), SHA256, or SHA512.  
	 * @param digits Number of digits in the code. Recommended: 6 or 8.
	 * @param counter Initial HOTP counter value. Required when provisioning a key for use with HOTP.
	 */
	public OTPAuthentication(byte[] secret, String issuer, String account,  
			HMACAlgorithmEnum algo, Integer digits, Long counter) {
		this(secret, issuer, account, algo, digits, null, counter);
	}
	
	private OTPAuthentication(byte[] secret, String issuer, String account,  
			HMACAlgorithmEnum algo, Integer digits, Integer period, Long counter) {
		if(secret == null || secret.length == 0) {
			throw new IllegalArgumentException("secret");
		}
		this.secret = secret;
		this.secretBase32 = new Base32().encodeAsString(secret);
		this.algo = algo;
		if(algo == null) {
			this.algo = HMACAlgorithmEnum.SHA1;
		}
		this.digits = digits;
		if(digits == null) {
			this.digits = 6;
		}
		
		if(period != null && counter != null) {
			throw new IllegalArgumentException("Either period or counter must be null (HOTP vs. TOTP).");
		}
		if(period == null && counter == null) {
			throw new IllegalArgumentException("Either period or counter must not be null (HOTP vs. TOTP).");
		}
		this.period = period;
		this.counter = counter;
		if(this.period == null) {
			this.type = "hotp";
		}
		else {
			this.type = "totp";
		}
		
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
	 * @return The OTP code for the current Unix time, if TOTP, or for the next counter, if HOTP.
	 */
	public String password() {
		if(this.counter == null) {
			return password(System.currentTimeMillis());
		}
		else {
			this.counter++;
			return password(this.counter);
		}
	}

	/**
	 * 
	 * @param unixTime
	 * @return The TOTP code for the given Unix time.
	 */
	public String password(long unixTime) {
		if(this.period == null) {
			throw new IllegalStateException("This is an instance of HOTP, not TOTP.");
		}
		long time = (unixTime/1000L)/this.period;
		int digits = 6;
		if(this.digits != null) {
			digits = this.digits;
		}
		return HmacOneTimePassword.generate(this.secret, time, digits, HMACAlgorithmEnum.SHA1);
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
	public String password(long unixTime, double step) {
		if(this.period == null) {
			throw new IllegalStateException("This is an instance of HOTP, not TOTP.");
		}
		return password(unixTime + (int)(step * this.period));
	}
}