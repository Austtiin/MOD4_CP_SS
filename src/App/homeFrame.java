//homeFrame.java
//This is the main home frame of the application

//This is more of the GUI side of the application and is where the user will interact with the application
//homeFrame.java
//This is the main home frame of the application

//This is more of the GUI side of the application and is where the user will interact with the application
package App;

import Solution.CryptoClass;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

//This is the main home frame of the application
public class homeFrame extends JFrame {


    //final JTextArea to display the output
    private final JTextArea displayArea;


    //This is the main constructor for the home frame
    public homeFrame() {
        CryptoClass crypto = new CryptoClass();

        setTitle("Encryption/Decryption");
        setSize(500, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout());

        Color backgroundColor = new Color(18, 18, 18);
        Color buttonColor = new Color(30, 215, 96);
        Color textColor = Color.WHITE;
        Font font = new Font("Proxima Nova", Font.BOLD, 16);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(5, 1, 10, 10));
        panel.setBackground(backgroundColor);
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        displayArea = new JTextArea();
        displayArea.setBackground(backgroundColor);
        displayArea.setForeground(textColor);
        displayArea.setFont(font);
        displayArea.setEditable(false);

        JButton fileEncryptButton = new JButton("Encrypt from file");
        fileEncryptButton.setBackground(buttonColor);
        fileEncryptButton.setForeground(textColor);
        fileEncryptButton.setFont(font);
        fileEncryptButton.setFocusPainted(false);

        fileEncryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    List<String> files = CryptoClass.listFiles();
                    String fileName = (String) JOptionPane.showInputDialog(null, "Choose file:", "File Selection",
                            JOptionPane.QUESTION_MESSAGE, null, files.toArray(), files.get(0));

                    if (fileName != null) {
                        String algorithm = (String) JOptionPane.showInputDialog(null, "Choose algorithm:", "Algorithm Selection",
                                JOptionPane.QUESTION_MESSAGE, null, new String[]{"AES", "Blowfish", "ChaCha20"}, "AES");

                        String newContent = JOptionPane.showInputDialog("Enter new content to encrypt:");

                        if (newContent != null) {
                            CryptoClass.updateFileWithEncryptedContent(fileName, newContent, algorithm);
                            displayArea.setText("File " + fileName + " has been updated with encrypted content.");
                        }
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
                }
            }
        });

        JButton fileDecryptButton = new JButton("Decrypt from file");
        fileDecryptButton.setBackground(buttonColor);
        fileDecryptButton.setForeground(textColor);
        fileDecryptButton.setFont(font);
        fileDecryptButton.setFocusPainted(false);

        fileDecryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    List<String> files = CryptoClass.listFiles();
                    String fileName = (String) JOptionPane.showInputDialog(null, "Choose file:", "File Selection",
                            JOptionPane.QUESTION_MESSAGE, null, files.toArray(), files.get(0));

                    if (fileName != null) {
                        String algorithm = (String) JOptionPane.showInputDialog(null, "Choose algorithm:", "Algorithm Selection",
                                JOptionPane.QUESTION_MESSAGE, null, new String[]{"AES", "Blowfish", "ChaCha20"}, "AES");

                        CryptoClass.updateFileWithDecryptedContent(fileName, algorithm);
                        displayArea.setText("File " + fileName + " has been updated with decrypted content.");
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
                }
            }
        });

        JButton inputButton = new JButton("Encrypt/Decrypt from keyboard input");
        inputButton.setBackground(buttonColor);
        inputButton.setForeground(textColor);
        inputButton.setFont(font);
        inputButton.setFocusPainted(false);

        inputButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String input = JOptionPane.showInputDialog("Enter text to encrypt:");

                    String algorithm = (String) JOptionPane.showInputDialog(null, "Choose algorithm:", "Algorithm Selection",
                            JOptionPane.QUESTION_MESSAGE, null, new String[]{"AES", "Blowfish", "ChaCha20"}, "AES");

                    crypto.processInput(input, algorithm);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
                }
            }
        });

        JButton exitButton = new JButton("Exit");
        exitButton.setBackground(buttonColor);
        exitButton.setForeground(textColor);
        exitButton.setFont(font);
        exitButton.setFocusPainted(false);

        exitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });

        panel.add(fileEncryptButton);
        panel.add(fileDecryptButton);
        panel.add(inputButton);
        panel.add(exitButton);

        add(panel, BorderLayout.CENTER);
        add(new JScrollPane(displayArea), BorderLayout.SOUTH);
        getContentPane().setBackground(backgroundColor);
    }}