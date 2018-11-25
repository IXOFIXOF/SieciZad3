import java.io.*;
import java.net.*;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

class Sign{
	
	Sign()
	{
		signedData = null;
	}
	byte[] signedData;
}
public class Client {
    public static void main(String[] args) throws IOException {

        FileInputStream fileInputStream = null;
		PublicKey publicKey = null;
		Signature signature = null;
		Sign sign = new Sign();
		try{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048); // KeySize
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
 
		PrivateKey privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
		
		byte[] data = "sign me".getBytes();
		signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(data);
		sign.signedData = signature.sign();
		}
		catch( NoSuchAlgorithmException e )
		{
			e.printStackTrace();
		}
		catch( SignatureException e )
		{
			e.printStackTrace();
		}
		catch( InvalidKeyException e )
		{
			e.printStackTrace();
		}
        //String Sign = new String( signedData, "UTF-8" );
        
        Socket socket = null;
        String host = "150.254.79.176";
        String key = "klucz";

        socket = new Socket(host, 4444);

		BigInteger r = new BigInteger( 1024, new Random());
		r = r.nextProbablePrime();
		BigInteger p; //= new BigInteger( 1024, new Random());
		while(true)
		{
			p = r.multiply( new BigInteger("2"));
			p = p.add( new BigInteger("1"));
	   		if( p.isProbablePrime(1) == true)
			{
				break;
			}
			else
			{
				r = r.nextProbablePrime();
			}
			
		}
		BigInteger q = new BigInteger( p.bitCount() - 1, new Random());
	    while(true)
		{
			BigInteger modP = new BigInteger("1");
			modP.mod( p );
			
			BigInteger testg2 = q.pow( 2 );
			BigInteger testgR = q.modPow( r, new BigInteger("1") );
			
			if( !testg2.equals( modP) && !testgR.equals( modP) )
			{
				break;
			}
     		else
			{	
				q = new BigInteger( p.bitCount(), new Random());
			} 
			
		}
		System.out.println("2");
		
        File file = new File("Client.pdf");
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
		System.out.println("4");
	//	os.writeObject( sign );
		os.writeObject( publicKey );
		dOut.writeUTF(p.toString());
		dOut.writeUTF(q.toString());
		System.out.println("5");
		Random random = new Random();
		BigInteger Xa = new BigInteger( p.bitCount() - 1, new Random() );//    random.nextInt(p-1)+1;
		System.out.println("Xa - " + Xa );
		
		BigInteger Ya = q.modPow( Xa, p );
		System.out.println("Ya - " + Ya );		
		dOut.writeUTF( Ya.toString() );
		
		BigInteger Yb = new BigInteger( dIn.readUTF());
		System.out.println( "Yb - " + Yb );
	
		BigInteger S = Yb.modPow(Xa, p);
		
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
