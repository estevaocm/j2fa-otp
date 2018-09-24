package j2fa.otp;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base32;

public class OTPAuth {
	
	private String type = "totp";
	private String issuer;
	private String account;
	private String secretHex; 
	private String secretBase32; 
	private String algo;
	private Integer digits;
	private Integer period;
	
	public OTPAuth(String secretHex, String issuer, String account,  
			String algo, Integer digits, Integer period) {
		if(secretHex == null || secretHex.isEmpty()) {
			throw new IllegalArgumentException("secretHex");
		}
		this.secretHex = secretHex;
		this.algo = algo;
		this.digits = digits;
		this.period = period;
		this.secretBase32 = new Base32().encodeAsString(HexUtils.hexToBytes(secretHex));
		this.issuer = issuer;
		this.account = account;
	}
	
	public OTPAuth(byte[] secret, String issuer, String account, 
			String algo, Integer digits, Integer period) {
		this(issuer, account, HexUtils.bytesToHex(secret), algo, digits, period);
	}
	
	/**
	 * 
	 * @return OTPAuth path for setting up the client. Usually presented as a QR code.
	 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	 */
	public String setupPath() {
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
		if(this.algo != null && !this.algo.isEmpty()) {//default: SHA1
			path += "&algorithm=" + this.algo;
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
		return generate(System.currentTimeMillis()/1000L);
	}

	/**
	 * 
	 * @param unixTime
	 * @return The TOTP code for the given Unix time.
	 */
	public String generate(long unixTime) {
		long time = unixTime/this.period;
		String step = "0000000000000000" + Long.toHexString(time).toUpperCase();
		step = step.substring(step.length() -16);
		String digits = "6";
		if(this.digits != null) {
			digits = this.digits.toString();
		}
		return TimebasedOneTimePassword.generate(this.secretHex, step, digits);
	}
}