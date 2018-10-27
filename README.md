# j2fa-otp
Library for one-time passwords for two-factor authentication. Supports TOTP and HOTP.

First of all, you will need to generate a random secret key, at least 20 bytes long.
You may call the included CryptoUtils.randomSeed(20) or use your own implementation.
The OTPAuthentication class provides the authentication services.
Simply instantiate with either the TOTP or the HOTP constructor, 
then call setupPath() to get the setup address
(which can be codified to a QR matriz using the QRCode class).
After the client sets up their device, call password() to compute the passcode
and verify the user input.
