package seguridad20222_cliente;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

public class Client{
    //.writeObject("exit");
    //
    public static void main(String[] args) throws UnknownHostException, IOException, ClassNotFoundException {
        Socket socket;
        socket = new Socket("127.0.0.1", 4030);
        PrintWriter ac = new PrintWriter(socket.getOutputStream() , true);
        ac.println(1);
        
        System.out.println("Received? ");
        


        
    }
    
}
