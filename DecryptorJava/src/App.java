import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import Decoder.BASE64Decoder;


public class App {
	public static void main(String args[]) throws Exception {
		String password = "Secret Passphrase";
		String salt = "4c5fdd196c41bd5d3c2088ba4cf69d48";
		String iv = "44aa42163c6820f1479df0e9ce4da3aa";
		String encrypted = "8hTqW6/N6s/XhC8fbBr9RQ==";
		byte[] saltBytes =DatatypeConverter.parseHexBinary(salt); // hexStringToByteArray(salt);
		byte[] ivBytes = DatatypeConverter.parseHexBinary(iv);// hexStringToByteArray(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec sKey = (SecretKeySpec) generateKeyFromPassword(password, saltBytes);
		System.out.println(decrypt(encrypted, sKey, ivParameterSpec));
	}

	public static SecretKey generateKeyFromPassword(String password, byte[] saltBytes) throws GeneralSecurityException {

		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), saltBytes, 100, 128);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		SecretKey secretKey = keyFactory.generateSecret(keySpec);
		return new SecretKeySpec(secretKey.getEncoded(), "AES");
	}

	public static String decrypt(String encryptedData, SecretKeySpec sKey, IvParameterSpec ivParameterSpec)
			throws Exception {

		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, sKey, ivParameterSpec);
		byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
		byte[] decValue = c.doFinal(decordedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}
}
