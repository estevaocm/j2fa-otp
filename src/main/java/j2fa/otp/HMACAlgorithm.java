package j2fa.otp;

public enum HMACAlgorithm {
	SHA1("HmacSHA1"),
	SHA256("HmacSHA256"),
	SHA512("HmacSHA512");
	
	private final String desc;
	
	HMACAlgorithm(String desc){
		this.desc = desc;
	}
	
	public String desc() {
		return this.desc();
	}

}
