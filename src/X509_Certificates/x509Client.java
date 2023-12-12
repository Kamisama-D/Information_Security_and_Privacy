package X509_Certificates;

import java.io.*;
import java.net.*;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import javax.crypto.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

public class x509Client {
	public static void main(String[] args) throws Exception {
		// start send socket
		String host = "192.168.1.155";
		int portSend = 7999;
		Socket socketSend = new Socket(host, portSend);
		// send certification request
		String requestMessage = "Certification Request";
		ObjectOutputStream socketOut = new ObjectOutputStream(socketSend.getOutputStream());
		byte[] byteRequest = requestMessage.getBytes();
		socketOut.writeObject(byteRequest);
		socketOut.close();
		// close send socket
		socketSend.close();

		// start receive socket
		int portReceive = 6999;
		ServerSocket server = new ServerSocket(portReceive);
		Socket socketServer = server.accept();
		// receive certification
		ObjectInputStream certIn = new ObjectInputStream(socketServer.getInputStream());
		X509Certificate X509cert = (X509Certificate) certIn.readObject();
		// close receive socket
		socketServer.close();
		server.close();

		// print received certification
		System.out.println("The Certification Received: " + X509cert + '\n');

		// verify certification
		Date now = new Date();
		try {
			X509cert.checkValidity(now);
			System.out.println("Certificate is successfully verified! " + "(Time of check: " + now.toString() + ")");
		} catch (CertificateExpiredException e) {
			System.out.print("Certificate expired on " + X509cert.getNotAfter());
			System.exit(0);
		} catch (CertificateNotYetValidException e) {
			System.out.print("Certificate is not valid until " + X509cert.getNotBefore());
			System.exit(0);
		}

		// verify the public key within the .X509cert file
		try {
			X509cert.verify(X509cert.getPublicKey());
			System.out.println("The public key from the certification is successfully verified!");
		} catch (InvalidKeyException e) {
			System.out.println("Public key is not valid with respect to the certification checked");
			System.exit(0);
		} catch (SignatureException e) {
			System.out.println("Signature exception");
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// get the server's public key from the certification
		RSAPublicKey serverPublicKey = (RSAPublicKey) X509cert.getPublicKey();
        //encrypt message with server's public key
		String message = "The quick brown fox jumps over the lazy dog.";
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedMessage = cipher.doFinal(message.getBytes());

		// wait for server to listen to message
		TimeUnit.SECONDS.sleep(1);

		// send encrypted message
		socketSend = new Socket(host, portSend);
		System.out.println("Send Message: " + message);
		ObjectOutputStream Out = new ObjectOutputStream(socketSend.getOutputStream());
        Out.writeObject(encryptedMessage);
		Out.close();
	    socketSend.close();
	}
}
