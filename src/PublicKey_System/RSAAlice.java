package PublicKey_System;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.*;

public class RSAAlice {
	public static void main(String[] args) throws Exception {
		String message = "The quick brown fox jumps over the lazy dog.";
		// String host = "paradox.sis.pitt.edu";
		String host = "192.168.1.155";
		int port = 7999;
		Socket s = new Socket(host, port);

		// -Generate Alice's RSA key pair.
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		RSAPublicKey AlicePubK = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey AlicePrivK = (RSAPrivateKey) keyPair.getPrivate();

		// -Store Alice's Public Key in a file where RSABob can access it.
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(
				"src/PublicKey_System/aliceKeyFile.xx"));
		out.writeObject(AlicePubK);
		out.close();

		// -Read Bob's Public Key
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(
				"src/PublicKey_System/bobKeyFile.xx"));
		RSAPublicKey BobPubK = (RSAPublicKey) in.readObject();
		in.close();

		// -Use the keys to encrypt the message above 
		// - 1. Use Alice's Private key -- Keep Authentication
		Cipher cipher1 = Cipher.getInstance("RSA");
		cipher1.init(Cipher.ENCRYPT_MODE, AlicePrivK);
		byte[] byteMsg = message.getBytes("UTF-8");
		byte[] encryptedMessage1 = cipher1.doFinal(byteMsg);
		
		// - 2. Use Bob's Public Key -- Keep Confidentiality
		Cipher cipher2 = Cipher.getInstance("RSA");
		cipher2.init(Cipher.ENCRYPT_MODE, BobPubK);
		byte[] encryptedMessage2 = cipher2.doFinal(encryptedMessage1);

		// and send it over socket s to Bob.
		ObjectOutputStream socketOut = new ObjectOutputStream(s.getOutputStream());
		socketOut.writeObject(encryptedMessage2);
		socketOut.close();
		s.close();
	}
}