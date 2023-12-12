package Signature;
import java.io.*;
import java.net.*;
import java.security.*;
import java.math.BigInteger;
 
public class ElGamalAlice
{
	private static BigInteger computeY(BigInteger p, BigInteger g, BigInteger d)
	{
		// IMPLEMENT THIS FUNCTION;
		// compute public key y using private key d, prime p and base g
		// y = g ^ d % p
		BigInteger y = g.modPow(d, p);
		return y;
	}

	private static BigInteger computeK(BigInteger p)
	{
		// IMPLEMENT THIS FUNCTION;
		// generate random k that is less than (p-1) and relatively prime to (p-1)
		// gcd(k, p-1) == 1 && k < p-1
		SecureRandom r = new SecureRandom();
		BigInteger k = new BigInteger(1024, r);
		while (k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE) != true || k.compareTo(p.subtract(BigInteger.ONE)) >= 0) {
			k = new BigInteger(1024, r);
		}
		return k;
	}
	
	private static BigInteger computeA(BigInteger p, BigInteger g, BigInteger k)
	{
		// IMPLEMENT THIS FUNCTION;
		// compute a that is part of the signature
		// a = g ^ k % p
		BigInteger a = g.modPow(k, p);
		return a;
	}

	private static BigInteger computeB(	String message, BigInteger d, BigInteger a, BigInteger k, BigInteger p)
	{
		// IMPLEMENT THIS FUNCTION;
		// compute b that is the other part of the signature
		// b = (H(message) - d*a) * k ^(-1) % (p-1)
		try {
			MessageDigest md = MessageDigest.getInstance("SHA");
			BigInteger hashedMessage = new BigInteger(md.digest(message.getBytes()));
			BigInteger inverseK = k.modInverse(p.subtract(BigInteger.ONE));
			BigInteger modulo = p.subtract(BigInteger.ONE);
			BigInteger b = hashedMessage.subtract(d.multiply(a)).multiply(inverseK).mod(modulo);
			return b;		
		} catch (NoSuchAlgorithmException e) {
			return null;
		}		
	}

	public static void main(String[] args) throws Exception 
	{
		String message = "The quick brown fox jumps over the lazy dog.";

		// String host = "paradox.sis.pitt.edu";
		String host = "192.168.1.155";
		int port = 7999;
		Socket s = new Socket(host, port);
		ObjectOutputStream os = new ObjectOutputStream(s.getOutputStream());

		// You should consult BigInteger class in Java API documentation to find out what it is.
		BigInteger y, g, p; // public key
		BigInteger d; // private key

		int mStrength = 1024; // key bit length
		SecureRandom mSecureRandom = new SecureRandom(); // a cryptographically strong pseudo-random number

		// Create a BigInterger with mStrength bit length that is highly likely to be prime.
		// (The '16' determines the probability that p is prime. Refer to BigInteger documentation.)
		p = new BigInteger(mStrength, 16, mSecureRandom);
		
		// Create a randomly generated BigInteger of length mStrength-1
		g = new BigInteger(mStrength-1, mSecureRandom);
		d = new BigInteger(mStrength-1, mSecureRandom);

		y = computeY(p, g, d);

		// At this point, you have both the public key and the private key. Now compute the signature.

		BigInteger k = computeK(p);
		BigInteger a = computeA(p, g, k);
		BigInteger b = computeB(message, d, a, k, p);

		// send public key
		os.writeObject(y);
		os.writeObject(g);
		os.writeObject(p);

		// send message
		os.writeObject(message);
		
		// send signature
		os.writeObject(a);
		os.writeObject(b);
		
		s.close();
	}
}
