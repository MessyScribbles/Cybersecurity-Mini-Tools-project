import java.io.*;
import java.net.*;
import java.util.*;

public class Main {
    private static Set<ClientHandler> clients = Collections.synchronizedSet(new HashSet<>());

    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(12345);
        System.out.println("[✔] Chat server started on port 12345...");

        // Thread to handle server (admin) messages
        new Thread(() -> {
            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            String msg;
            try {
                while ((msg = consoleReader.readLine()) != null) {
                    broadcast("SERVER: " + msg);
                }
            } catch (IOException e) {
                System.out.println("[!] Server input error.");
            }
        }).start();

        // Accept clients
        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("[+] New client connected.");
            ClientHandler handler = new ClientHandler(socket);
            clients.add(handler);
            handler.start();
        }
    }

    // Broadcast to all clients
    private static void broadcast(String message) {
        synchronized (clients) {
            for (ClientHandler client : clients) {
                client.send(message);
            }
        }
    }

    static class ClientHandler extends Thread {
        private Socket socket;
        private PrintWriter out;
        private BufferedReader in;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        public void send(String message) {
            if (out != null) {
                out.println(message);
            }
        }

        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                String msg;
                while ((msg = in.readLine()) != null) {
                    System.out.println("Client: " + msg);
                    broadcast("Client: " + msg);  // Optionally remove to avoid echoing
                }
            } catch (IOException e) {
                System.out.println("[!] Client disconnected.");
            } finally {
                try { socket.close(); } catch (IOException e) {}
                clients.remove(this);
            }
        }
    }
}
