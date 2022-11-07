

import java.net.Socket;
import java.util.Scanner;

public class Client{
    //.writeObject("exit");
    //
    private Socket socket;
    public static void main(String[] args) {

        Scanner myObj = new Scanner(System.in);
        System.out.println("Enter number of clients:");
        Integer numClients = myObj.nextInt();
        myObj.close();

        for (int i = 0; i < numClients; i++) {
            //It says one delegate for each client 
            try {
                Socket socket = new Socket("localhost", 4030);
                ClientThread client = new ClientThread(socket, i);
                client.start();
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            
        }
    }
}
