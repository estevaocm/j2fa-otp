# j2fa-otp
Library for one-time passwords for two-factor authentication. Supports TOTP and HOTP.

The OTPAuthentication class provides the authentication services.
Simply instantiate with the TOTP or HOTP constructor, 
then call setupPath() to get the setup address
(which can be codified to a QR matriz using the QRCode class), 
then password() to compute the password code. 
