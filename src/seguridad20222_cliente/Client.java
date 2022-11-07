package seguridad20222_cliente;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client{

    //  Code from SrvThead.java
    public static byte[] str2byte( String ss)
    {	
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length()/2];
        for (int i = 0 ; i < ret.length ; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
        }
        return ret;
    }

    public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException {
        Socket socket;
        socket = new Socket("127.0.0.1", 4030);
        PrintWriter ac = new PrintWriter(socket.getOutputStream() , true);
        ac.println("SECURE INIT");

        //  Step 3
        BufferedReader dc = new BufferedReader(new InputStreamReader(socket.getInputStream()));	 
		String G = dc.readLine();
        String P = dc.readLine();
        String G2X = dc.readLine();
        String Sign = dc.readLine();
        System.out.println("Received G:"+ G);
        System.out.println("Received P:"+ P);
        System.out.println("Received G2X:"+ G2X);
        System.out.println("Received Sign:"+ Sign);

        //  Step 4
        FileInputStream is1;
		PublicKey pubkeyserver = null;
		try {
			is1 = new FileInputStream("datos_asim_srv.pub");
			File f = new File("datos_asim_srv.pub");
			byte[] inBytes1 = new byte[(int)f.length()];
			is1.read(inBytes1);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(inBytes1);
			pubkeyserver = kf.generatePublic(publicKeySpec);
			is1.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
        String msg = G + "," + P + "," + G2X;
        try {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(pubkeyserver);
            publicSignature.update(msg.getBytes(StandardCharsets.UTF_8));
            boolean isCorrect = publicSignature.verify(str2byte(Sign));

            // Step 5
            if (isCorrect) {
                System.out.println("True");
                ac.println("OK");
            } else {
                System.out.println("False");
                ac.println("ERROR");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        //  Step 6a
        BigInteger p = new BigInteger(P);
        BigInteger g = new BigInteger(G);
        SecureRandom r = new SecureRandom();
		int y = Math.abs(r.nextInt());
        Long longy = Long.valueOf(y);
        BigInteger biy = BigInteger.valueOf(longy);
        BigInteger valor_comun = g.modPow(biy,p);
        String str_valor_comun = valor_comun.toString();
        System.out.println("G2Y:" + str_valor_comun);

        //  Step 6b
        ac.println(str_valor_comun);

        //  Step 7a
        BigInteger g2x = new BigInteger(G2X);
        BigInteger llave_maestra = g2x.modPow(biy,p);
        String str_llave = llave_maestra.toString();
        System.out.println("G2XY:" + str_llave);

        // Derive symmetric keys
        byte [] byte_semilla;
        MessageDigest digest;
        byte[] encodedhash;
        SecretKey k_ab1 = null;
        SecretKey k_ab2 = null;
        //  k_ab1
        try {
            byte_semilla = str_llave.trim().getBytes(StandardCharsets.UTF_8);
            digest = MessageDigest.getInstance("SHA-512");
            encodedhash = digest.digest(byte_semilla);
            byte[] encoded1 = new byte[32];
            for (int i = 0; i < 32 ; i++) {
                encoded1[i] = encodedhash[i];
            }
            k_ab1 = new SecretKeySpec(encoded1,"AES");	
        } catch (Exception e) {
            e.printStackTrace();
        }

        //  k_ab2
        try {
            byte_semilla = str_llave.trim().getBytes(StandardCharsets.UTF_8);
            digest = MessageDigest.getInstance("SHA-512");
            encodedhash = digest.digest(byte_semilla);
            byte[] encoded2 = new byte[32];
            for (int i = 32; i < 64 ; i++) {
                encoded2[i-32] = encodedhash[i];
            }
            k_ab2 = new SecretKeySpec(encoded2,"AES");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //  Generate iv1
        byte[] iv1 = new byte[16];
	    new SecureRandom().nextBytes(iv1);

        //  Step 8


        System.out.println("Closing Stream");
        socket.close();
        
    }
    
}
