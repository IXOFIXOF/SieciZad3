import java.io.*;
import java.net.*;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.Random;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

class Data implements Serializable{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	Data()
	{
		signedData = null;
		data = null;
	}
	byte[] signedData;
	byte[] data;
	PublicKey publicKey;
}
class Hellman implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public BigInteger p;
	public BigInteger q;
	public BigInteger Ya;
}
public class Server  {
    

	public static void main(String[] args) throws IOException {

       Data data = null;
       Signature signature = null;
       Hellman hellman = null;
	try {
		signature = Signature.getInstance("SHA256withRSA");
	} catch (NoSuchAlgorithmException e1) {
		// TODO Auto-generated catch block
		e1.printStackTrace();
	}
        ServerSocket serverSocket = null;
        String key = "brakklucza";


        try {
            serverSocket = new ServerSocket(4444);
        } catch (IOException ex) {
            System.out.println("Can't setup server on this port number. ");
        }

        Socket socket = null;
        DataInputStream in = null;
        FileOutputStream out = null;



        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.println("Can't accept client connection. ");
        }

        try {
            in = new DataInputStream(socket.getInputStream());
        } catch (IOException ex) {
            System.out.println("Can't get socket input stream. ");
        }

        try {
            out = new FileOutputStream("Nowy dokument tekstowy1.txt");
        } catch (FileNotFoundException ex) {
            System.out.println("File not found. ");
        }

        DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
        ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());

        byte[] bytes = new byte[16*4096];

        int count;
        try {

            data = (Data) is.readObject();
            hellman = convertFromBytes( data.data );

            signature.initVerify(data.publicKey);
            signature.update(data.data);
            if(signature.verify(data.signedData)){
                System.out.println("Verified");
            }else{
                System.out.println("Something is wrong");
            }
        }
        catch (Exception e)
        {

        }



        
        System.out.println("P: "+hellman.p);
        System.out.println("Q: "+hellman.q);
        
        BigInteger Xb = new BigInteger (hellman.p.bitCount()-1, new Random());//rand.nextInt(p-1)+1;
        System.out.println("Xb: "+Xb);

        BigInteger Yb = hellman.q.modPow(Xb, hellman.p);
        System.out.println("Yb: "+Yb);
        

        dOut.writeUTF(Yb.toString());

        
        System.out.println("Ya: "+hellman.Ya);


        BigInteger S_B = hellman.Ya.modPow(Xb, hellman.p);

        System.out.println("S: "+S_B);

        key = S_B.toString();


        int length = in.readInt();
        if (length > 0) {
            byte[] message = new byte[length];
            in.readFully(message, 0, message.length);
            try {
                byte[] b2 = AES.decrypt(message, key);
                out.write(b2, 0, b2.length);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }


        out.close();
        in.close();
        socket.close();
        serverSocket.close();
    }
    private static Hellman convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInput in = new ObjectInputStream(bis)) {
            return (Hellman)in.readObject();
        } 
    }
}

class AES {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    private static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(byte[] Data, String secret) throws Exception {
        setKey(secret);
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encVal = c.doFinal(Data);
        return encVal;
    }

    public static byte[] decrypt(byte[] encryptedData, String secret) throws Exception {
        setKey(secret);
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decValue = c.doFinal(encryptedData);
        return decValue;
    }
}
