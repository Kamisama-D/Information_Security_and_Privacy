package Signature;
import java.io.*;
import java.net.*;
import java.security.*;
import java.math.BigInteger;

public class ElGamalBob
{
	private static boolean verifySignature(	BigInteger y, BigInteger g, BigInteger p, BigInteger a, BigInteger b, String message)
	{
		// IMPLEMENT THIS FUNCTION;
		// the signature is valid if y^a * a^b % p == g^hashedMessage % p
		// public key components (y, g, p), the signature components (a, b)
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			BigInteger hashedMessage = new BigInteger(md.digest(message.getBytes()));
			
			BigInteger part1 = y.modPow(a, p).multiply(a.modPow(b, p)).mod(p);
			BigInteger part2 = g.modPow(hashedMessage, p);
					
			return part1.equals(part2);
		} catch (NoSuchAlgorithmException e) {
			return false;
		}
	}

	public static void main(String[] args) throws Exception 
	{
		int port = 7999;
		ServerSocket s = new ServerSocket(port);
		Socket client = s.accept();
		ObjectInputStream is = new ObjectInputStream(client.getInputStream());

		// read public key
		BigInteger y = (BigInteger)is.readObject();
		BigInteger g = (BigInteger)is.readObject();
		BigInteger p = (BigInteger)is.readObject();

		// read message
		String message = (String)is.readObject();

		// read signature
		BigInteger a = (BigInteger)is.readObject();
		BigInteger b = (BigInteger)is.readObject();

		boolean result = verifySignature(y, g, p, a, b, message);

		System.out.println(message);

		if (result == true)
			System.out.println("Signature verified.");
		else
			System.out.println("Signature verification failed.");

		s.close();
	}
}