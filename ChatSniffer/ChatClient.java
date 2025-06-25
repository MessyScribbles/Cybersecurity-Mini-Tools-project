import java.io.*;
import java.net.*;

public class ChatClient {
    public static void main(String[] args) {
        String serverAddress = "localhost"; // or your LAN IP
        int port = 12345;

        try (
                Socket socket = new Socket(serverAddress, port);
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
                PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
        ) {
            System.out.println("Connected to chat server.");

            // Thread to read messages from server
            new Thread(() -> {
                String line;
                try {
                    while ((line = input.readLine()) != null) {
                        System.out.println(line);
                    }
                } catch (IOException e) {
                    System.out.println("Disconnected from server.");
                }
            }).start();

            // Main loop to send user input
            String userMsg;
            while ((userMsg = userInput.readLine()) != null) {
                output.println(userMsg);
            }

        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
