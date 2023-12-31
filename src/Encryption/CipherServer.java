package Encryption;
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

public class CipherServer
{
	public static void main(String[] args) throws Exception 
	{
		int port = 7999;
		ServerSocket server = new ServerSocket(port);
		Socket s = server.accept();

		// YOU NEED TO DO THESE STEPS:
		// -Receive the encrypted message
		ObjectInputStream oIn = new ObjectInputStream(s.getInputStream());
		byte[] byteMessage = (byte[]) oIn.readObject();
		oIn.close();
		s.close();
		
		// -Read the key from the file generated by the client.
		ObjectInputStream keyIn = new ObjectInputStream(new FileInputStream("src/Encryption/desKeyFile.xx"));
		Key desKey = (Key) keyIn.readObject();
		keyIn.close();
		
		// -Use the key to decrypt the incoming message from socket s.		
		
		// Decrypt the message
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.DECRYPT_MODE, desKey);
		String decryptedMessage = new String(cipher.doFinal(byteMessage));
		
		// -Print out the decrypt String to see if it matches the orignal message.
		System.out.println("The message sent from the client is: " + decryptedMessage);
		server.close();
	}
}