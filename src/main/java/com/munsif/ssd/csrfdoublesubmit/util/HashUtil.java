package com.munsif.ssd.csrfdoublesubmit.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {

	/**
	 * Returns the Hash Value of a given string
	 * 
	 * @param plainText
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public static String getHashValue(String plainText) throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return bytesToHex(digest.digest(plainText.getBytes(StandardCharsets.UTF_8)));
	}

	private static String bytesToHex(byte[] hash) {
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}
		return hexString.toString();
	}
}
