package PublicKey_System;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.*;

public class RSABob {
	public static void main(String[] args) throws Exception {
		// -Generate Bob's RSA key pair.
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048, new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		RSAPublicKey BobPubK = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey BobPrivK = (RSAPrivateKey) keyPair.getPrivate();

		// -Store Bob's Public Key in a file where RSAAlice can access it.
		ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(
				"src/PublicKey_System/bobKeyFile.xx"));
		out.writeObject(BobPubK);
		out.close();

		// server
		int port = 7999;
		ServerSocket server = new ServerSocket(port);
		Socket s = server.accept();

		// -Receive the encrypted message
		ObjectInputStream socketIn = new ObjectInputStream(s.getInputStream());
		byte[] byteMessage = (byte[]) socketIn.readObject();
		socketIn.close();
		s.close();

		// -Read Alice's Public key.
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(
				"src/PublicKey_System/aliceKeyFile.xx"));
		RSAPublicKey AlicePubK = (RSAPublicKey) in.readObject();
		in.close();

		// -Use the keys to decrypt the incoming message from socket s.		
		// 1. Decrypt the message with Bob's Private Key
		Cipher cipher1 = Cipher.getInstance("RSA");
		cipher1.init(Cipher.DECRYPT_MODE, BobPrivK);
		byte[] decryptedMessage1 = cipher1.doFinal(byteMessage);
		
		// 2. Decrypt the message with Alice's Public Key
		Cipher cipher2 = Cipher.getInstance("RSA");
		cipher2.init(Cipher.DECRYPT_MODE, AlicePubK);
		byte[] decryptedMessage2 = cipher2.doFinal(decryptedMessage1);

		// -Print out the decrypt String to see if it matches the orignal message.
		String finalMsg = new String(decryptedMessage2);
		System.out.println("The message sent from Alice is: " + finalMsg);
		server.close();
	}
}