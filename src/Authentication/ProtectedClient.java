package Authentication;
import java.io.*;
import java.net.*;
import java.security.*;

public class ProtectedClient
{
	public void sendAuthentication(String user, String password, OutputStream outStream) throws IOException, NoSuchAlgorithmException 
	{
		DataOutputStream out = new DataOutputStream(outStream);

		// IMPLEMENT THIS FUNCTION.
		long t1 = System.currentTimeMillis();
		double q1 = Math.random();
		byte[] digest1 = Protection.makeDigest(user, password, t1, q1);
		
		long t2 = System.currentTimeMillis();
		double q2 = Math.random();
		byte[] digest2 = Protection.makeDigest(digest1, t2, q2);
		
		out.writeUTF(user);
		out.writeDouble(q1);
		out.writeLong(t1);
		out.writeInt(digest1.length);
		out.write(digest1);
		
		out.writeDouble(q2);
		out.writeLong(t2);
		out.writeInt(digest2.length);
		out.write(digest2);
		
		out.flush();
	}

	public static void main(String[] args) throws Exception 
	{
		// String host = "paradox.sis.pitt.edu";
		String host = "192.168.1.155";
		int port = 7999;
		String user = "George";
		String password = "abc123";
		Socket s = new Socket(host, port);

		ProtectedClient client = new ProtectedClient();
		client.sendAuthentication(user, password, s.getOutputStream());

		s.close();
	}
}