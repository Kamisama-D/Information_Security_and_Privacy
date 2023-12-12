package Message_Digest;

import java.security.*;

public class HashGenerator {
	public static void main(String[] args) {
		if (args.length > 0) {
			byte[] inputDataBytes = args[0].getBytes();
			StringBuilder md5Hash = generateHash(inputDataBytes, "MD5");
			StringBuilder shaHash = generateHash(inputDataBytes, "SHA");
			
			System.out.println("MD5 Hash: " + md5Hash.toString());
			System.out.println("SHA Hash: " + shaHash.toString());
		} else {
			System.out.println("No string provided to hash.");
		}
		
	}
	
	private static StringBuilder generateHash(byte[] dataBytes, String algorithm) {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(dataBytes);
			byte[] byteHash = md.digest();
			return byteToHex(byteHash);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Algorithm not found: " + algorithm);
			return null;
		}
		 
	}
	
	private static StringBuilder byteToHex(byte[] bytes) {
		StringBuilder hexString = new StringBuilder();
		for (byte b : bytes) {
			hexString.append(String.format("%02x", b & 0xFF));
		}
		return hexString;
	}
}
