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


public class Main {
    public static void main(String[] args) throws IOException {

        PublicKey publicKey = null;
        Signature signature = null;
        byte[] data = null;
        byte[] signedData = null;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // KeySize
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();


            data = "sign me".getBytes();


        }
        catch( NoSuchAlgorithmException e )
        {
            e.printStackTrace();
        }





        ServerSocket serverSocket = null;
        String key = "brakklucza";

        Random rand = new Random();



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
            out = new FileOutputStream("./wyk.pdf");
        } catch (FileNotFoundException ex) {
            System.out.println("File not found. ");
        }

        DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
        ObjectInputStream is = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream os = new ObjectOutputStream(socket.getOutputStream());

        byte[] bytes = new byte[16*4096];

        int count;




        try {

            publicKey = (PublicKey) is.readObject();


            signature.initVerify(publicKey);
            signature.update(data);
            if(signature.verify(signedData)){
                System.out.println("Verified");
            }else{
                System.out.println("Something is wrong");
            }
        }
        catch (Exception e)
        {

        }



        BigInteger p = new BigInteger (in.readUTF());
        System.out.println("P: "+p);
        BigInteger q = new BigInteger (in.readUTF());
        System.out.println("Q: "+q);
        BigInteger Xb = new BigInteger (p.bitCount()-1, new Random());//rand.nextInt(p-1)+1;
        System.out.println("Xb: "+Xb);

        BigInteger Yb = q.modPow(Xb, p);
        System.out.println("Yb: "+Yb);
        dOut.writeUTF(Yb.toString());

        BigInteger Ya = new BigInteger (in.readUTF());
        System.out.println("Ya: "+Ya);


        BigInteger S_B =Ya.modPow(Xb, p);

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
