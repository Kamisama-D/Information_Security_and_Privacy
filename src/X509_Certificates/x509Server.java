package X509_Certificates;

import java.io.*;
import java.net.*;
import javax.crypto.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class x509Server {
	public static void main(String[] args) throws Exception {
		// set alias and password
		String alias = "jenny";
		char[] password = "123456".toCharArray();

		// start server
		int port = 7999;
		ServerSocket server = new ServerSocket(port);
		System.out.println("Listening for Certification Request...");
		Socket socketServer = server.accept();

		// receive certification request
		ObjectInputStream in = new ObjectInputStream(socketServer.getInputStream());
		byte[] byteMessage = (byte[]) in.readObject();
		String reqMessage = new String(byteMessage);
		in.close();

		// if not receive the certification request, keep listening
		while (!reqMessage.equals("Certification Request")) {
			socketServer = server.accept();

			// receive certification request
			in = new ObjectInputStream(socketServer.getInputStream());
			byteMessage = (byte[]) in.readObject();
			reqMessage = byteMessage.toString();
			in.close();
			System.out.println(reqMessage);
		}

		// print request received
		System.out.println("Received " + reqMessage);

		// read certification file
		FileInputStream certIn = new FileInputStream("src/X509_Certificates/x509Server.cer");
		CertificateFactory certfFact = CertificateFactory.getInstance("X.509");
		X509Certificate X509cert = (X509Certificate)certfFact.generateCertificate(certIn);

		// start send socket
		String host = "192.168.1.155";
		int portSend = 6999;
		Socket socketSend = new Socket(host, portSend);
		// send certification
		ObjectOutputStream socketOut = new ObjectOutputStream(socketSend.getOutputStream());
		socketOut.writeObject(X509cert);
		socketOut.close();
		// close send socket
		socketSend.close();

		// start listen for receiving message again
		System.out.println("Listening for Message...");
		socketServer = server.accept();

		// receive message
		ObjectInputStream inMsg = new ObjectInputStream(socketServer.getInputStream());
		byteMessage = (byte[]) inMsg.readObject();
		inMsg.close();

		// close server
		socketServer.close();
		server.close();

		// read keystore and server's private key
		KeyStore kstore = KeyStore.getInstance("jks");
		kstore.load(new FileInputStream("src/X509_Certificates/keyStore.jks"), password);
		PrivateKey privateKey = (PrivateKey)kstore.getKey(alias, password);

		// decrypt the message
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedMsg = cipher.doFinal(byteMessage);

		// print message
		String message = new String(decryptedMsg);
		System.out.println("Message Received: " + message);
	}
}
