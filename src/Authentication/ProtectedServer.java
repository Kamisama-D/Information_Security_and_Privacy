package Authentication;
import java.io.*;
import java.net.*;
import java.security.*;

public class ProtectedServer
{
	public boolean authenticate(InputStream inStream) throws IOException, NoSuchAlgorithmException 
	{
		DataInputStream in = new DataInputStream(inStream);

		// IMPLEMENT THIS FUNCTION.
		String user = in.readUTF();
	    double q1 = in.readDouble();
	    long t1 = in.readLong();
	    int length1 = in.readInt();
	    byte[] digest1 = new byte[length1];
	    in.readFully(digest1);
	    
	    double q2 = in.readDouble();
	    long t2 = in.readLong();
	    int length2 = in.readInt();
	    byte[] digest2 = new byte[length2];
	    in.readFully(digest2);
	    
	    String realPassword = lookupPassword(user);
	    
	    byte[] reDigest1 = Protection.makeDigest(user, realPassword, t1, q1);
	    byte[] reDigest2 = Protection.makeDigest(reDigest1, t2, q2);
	    
	    return MessageDigest.isEqual(digest1, reDigest1) && MessageDigest.isEqual(digest2, reDigest2);
	}

	protected String lookupPassword(String user) { return "abc123"; }

	public static void main(String[] args) throws Exception 
	{
		int port = 7999;
		ServerSocket s = new ServerSocket(port);
		Socket client = s.accept();

		ProtectedServer server = new ProtectedServer();

		if (server.authenticate(client.getInputStream()))
		  System.out.println("Client logged in.");
		else
		  System.out.println("Client failed to log in.");

		s.close();
	}
}