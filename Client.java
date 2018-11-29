
import java.io.*;
import java.net.*;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.util.Random;
import java.math.BigInteger;
import java.security.*;

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
public class Client {
    public static void main(String[] args) throws IOException {

    	
        FileInputStream fileInputStream = null;
        Data data = new Data();
        Hellman hellman = new Hellman();
        Signature signature = null;
        PrivateKey privateKey = null;
        try{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048); // KeySize
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
 
		privateKey = keyPair.getPrivate();
		data.publicKey = keyPair.getPublic();
		
		}
		catch( NoSuchAlgorithmException e )
		{
			e.printStackTrace();
		}
        //String Sign = new String( signedData, "UTF-8" );
        
        Socket socket = null;
        String host = "localhost";
        String key = "klucz";

        socket = new Socket(host, 4444);

		BigInteger r = new BigInteger( 1024, new Random());
		r = r.nextProbablePrime();
		hellman.p = null; //= new BigInteger( 1024, new Random());
		hellman.q = null;
		while(true)
		{
			hellman.p = r.multiply( new BigInteger("2"));
			hellman.p = hellman.p.add( new BigInteger("1"));
	   		if( hellman.p.isProbablePrime(1) == true)
			{
				break;
			}
			else
			{
				r = r.nextProbablePrime();
			}
			
		}
		hellman.q = new BigInteger( hellman.p.bitCount() - 1, new Random());
	    while(true)
		{
			BigInteger modP = new BigInteger("1");
			modP.mod( hellman.p );
			
			BigInteger testg2 = hellman.q.pow( 2 );
			BigInteger testgR = hellman.q.modPow( r, new BigInteger("1") );
			
			if( !testg2.equals( modP) && !testgR.equals( modP) )
			{
				break;
			}
     		else
			{	
     			hellman.q = new BigInteger( hellman.p.bitCount(), new Random());
			} 
			
		}
		System.out.println("2");
		
        File file = new File("Nowy dokument tekstowy.txt");
        byte[] bFile = new byte[(int) file.length()];
        byte[] bytes = new byte[16 * 4096];

		System.out.println("3");
        fileInputStream = new FileInputStream(file);
        fileInputStream.read(bFile);

        OutputStream out = socket.getOutputStream();
		//ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());
        DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
		DataInputStream dIn = new DataInputStream(socket.getInputStream());
		
		Random random = new Random();
		BigInteger Xa = new BigInteger( hellman.p.bitCount() - 1, new Random() );//    random.nextInt(p-1)+1;
		System.out.println("Xa - " + Xa );
		
		hellman.Ya = hellman.q.modPow( Xa, hellman.p );
		System.out.println("Ya - " + hellman.Ya );		
		
		
		
		try {
			data.data = convertToBytes( hellman );
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
			signature.update(data.data);
			data.signedData = signature.sign();
		} 
		catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		catch (SignatureException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		
		
		os.writeObject( data );
		
		
		int i = dIn.readInt();
		System.out.println("test3");
		BigInteger Yb = new BigInteger( dIn.readUTF());
		System.out.println( "Yb - " + Yb );
	
		BigInteger S = Yb.modPow(Xa, hellman.p);
		
		System.out.println("S - " + S );
		
        key = S.toString();
        try {        
            byte [] b = AES.encrypt(bFile, key);
            dOut.writeInt(b.length); // write length of the message
            dOut.write(b); 
        } catch (Exception e) {
            e.printStackTrace();
        }
       

        out.close();
        socket.close();
    }
    private static byte[] convertToBytes(Hellman hellman) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(hellman);
            return bos.toByteArray();
        } 
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
