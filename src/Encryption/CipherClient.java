package Encryption;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
 
public class CipherClient
{
	public static void main(String[] args) throws Exception 
	{
		String message = "The quick brown fox jumps over the lazy dog.";
		// String host = "paradox.sis.pitt.edu";
		String host = "192.168.1.155";
		int port = 7999;
		Socket s = new Socket(host, port);

		// YOU NEED TO DO THESE STEPS:
		// -Generate a DES key.
		Key desKey = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("DES");
			keyGen.init(56, new SecureRandom());
			desKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			System.exit(0);
		}
		
		// -Store it in a file.
		FileOutputStream fos = new FileOutputStream("src/Encryption/desKeyFile.xx");
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(desKey);
		oos.close();
		
		// -Use the key to encrypt the message above 			
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, desKey);
		byte[] encryptedMessage = cipher.doFinal(message.getBytes("UTF-8"));		
		
		
		// and send it over socket s to the server.
		ObjectOutputStream oOut = new ObjectOutputStream(s.getOutputStream());
		oOut.writeObject(encryptedMessage);
		oOut.close();
		s.close();
	}
}
