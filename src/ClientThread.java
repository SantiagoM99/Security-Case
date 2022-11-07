

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientThread extends Thread{
    private Socket socket = null;
    private int id;
    private String dlg;
    private SecurityFunctions f = new SecurityFunctions();
    
    public ClientThread(Socket socket, int i) {
        this.socket = socket;
        this.id = i;
        this.dlg = new String("concurrent server " + i + ": ");
    }
    public void run() {
        
        try {

            PublicKey publicaServidor = f.read_kplus("datos_asim_srv.pub",dlg);
	        PrintWriter ac = new PrintWriter(socket.getOutputStream() , true);
	        BufferedReader dc = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            //Step 1: Sends the first confirmation
            ac.println("SECURE INIT");

            //Step 4.1: Receives P,G and G^x
            String G = dc.readLine();
            String P = dc.readLine();
            String G2X = dc.readLine();
            String signature = dc.readLine();
            byte[] signature_bytes = str2byte(signature);
            String msj = G+","+P+","+G2X;

            //Step 4.2: Check the signature
            long startSign = System.nanoTime();
            Boolean checker = f.checkSignature(publicaServidor, signature_bytes, msj);
            long endSign = System.nanoTime();      
            System.out.println("Client-"+ id +": --- Elapsed Time for checking signature in nano seconds: "+ (endSign-startSign));   
            // Step 5: Sends the result of the Test

            if (Boolean.TRUE.equals(checker)) {

                ac.println("OK");
                System.out.println(dlg + "Signature is valid");
                //Step 6a: Generates G^y

            SecureRandom r = new SecureRandom();
			int y = Math.abs(r.nextInt());
    		Long longy = Long.valueOf(y);
            BigInteger bix = BigInteger.valueOf(longy);
    		BigInteger g = new BigInteger(G);
            BigInteger p = new BigInteger(P);
            BigInteger g2x = new BigInteger(G2X);
            BigInteger valor_comun = G2Y(g,bix,p);

            //Step 6b: Sends G^y

            ac.println(valor_comun.toString());

            //Step 7a: Calculates master key

    		BigInteger master_key = calculate_master_key(g2x,bix,p);
    		String str_key = master_key.toString();

            // Generating symmetric key to cypher: K_AB1

			SecretKey sk_srv = f.csk1(str_key);

            // Generating symmetric key for: HMAC K_AB2

			SecretKey sk_mac = f.csk2(str_key);

            // Generating iv1

            byte[] iv1 = generateIvBytes();
	        String str_iv1 = byte2str(iv1);
			IvParameterSpec ivSpec1 = new IvParameterSpec(iv1);
            
            // Generating number request(Consulta)
            Random rand = new Random();
            int n = rand.nextInt(100);
            String request_str = String.valueOf(n);
            byte[] request_bytes = request_str.getBytes();
            byte[] rta_req = f.senc(request_bytes, sk_srv,ivSpec1, "Client-"+id+": ");
            long startHmac = System.nanoTime();
	        byte [] rta_mac = f.hmac(request_bytes, sk_mac);
            long endHmac = System.nanoTime();      
	        System.out.println("Client-"+ id +": --- Elapsed Time for generating HMAC in nano seconds: "+ (endHmac-startHmac));   

            //Step 8: Send cyphered request

            ac.println(byte2str(rta_req));
            ac.println(byte2str(rta_mac));
            ac.println(str_iv1);
            
            String response = dc.readLine();
            System.out.println(dlg + "Respuesta del servidor: " + response);
            //Step 10
            if (response.compareTo("OK")==0) {

                //Step 11

                String response_req = dc.readLine();
                String response_mac= dc.readLine();
                String str_iv2 = dc.readLine();

                //C(K_AB1,<rta>)

                byte[] response_req_bytes = str2byte(response_req);

                //HMAC(K_AB2,<rta>)

                byte[] response_mac_bytes = str2byte(response_mac);

                //iv2

                byte[] iv2_bytes = str2byte(str_iv2);
                IvParameterSpec ivSpec2 = new IvParameterSpec(iv2_bytes);

                //Step 12:
                //Deciphering answer:

                byte[] answer = f.sdec(response_req_bytes, sk_srv, ivSpec2);

                //Verifying C(K_AB1,<rta>) and HMAC(K_AB2,<rta>)

                Boolean verify = f.checkInt(answer, sk_mac, response_mac_bytes);
			    System.out.println(dlg + "Integrity check:" + verify); 

                //Step 13:
                if (verify) {
                    
                    ac.println("OK");

                }else{

                    ac.println("ERROR");

                }
            } 

            }else{

                ac.println("ERROR");
                System.out.println(dlg + "Signature is invalid");

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
        	
    public byte[] str2byte(String ss)
	{	
		// Encapsulamiento con hexadecimales

		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public String byte2str( byte[] b )
	{	
		// Encapsulamiento con hexadecimales

		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}

    private BigInteger G2Y(BigInteger base, BigInteger exponente, BigInteger modulo) {
        long start = System.nanoTime();
		BigInteger result = base.modPow(exponente,modulo);
        long end = System.nanoTime();      
	    System.out.println("Cliente-"+id+": --- Elapsed Time for generating G2Y in nano seconds: "+ (end-start));   
        return result;
    }

    private BigInteger calculate_master_key(BigInteger base, BigInteger exponente, BigInteger modulo) {
		return base.modPow(exponente, modulo);
	}

    private byte[] generateIvBytes() {
	    byte[] iv = new byte[16];
	    new SecureRandom().nextBytes(iv);
	    return iv;
	}

}
