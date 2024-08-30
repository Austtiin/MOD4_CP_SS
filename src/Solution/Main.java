//main.java
//This is where we will have the main method to run the program

//Austin Stephens
//Rasmussen University
//CEN4071C
//Professor Zayaz
//08/28/2024

//This is the main class that will run the program
//We have moved over our code and cleaned it up to make it more readable.


/*
This week you will continue with the Java benchmarking application for different encryption algorithms which will take file and keyboard input, perform data validation on the input, implement existing Java APIs to encrypt and decrypt the input, and provide the results of performance-based test cases.

Extend your Java program so that it also:

integrates ChaCha to encrypt and then decrypt using keyboard input
integrates ChaCha to encrypt and then decrypt using file input
displays appropriate messages during execution to inform the user of progress


Your Java program must include the points above, and include zero syntax or runtime errors, be logically and stylistically designed,
*/


//THis week we will be adding the ChaCha encryption algorithm to our program
package Solution;
import App.homeFrame;
import javax.swing.*;

public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {



            //start main frame of the application
            //set to visible
            homeFrame mainFrame = new homeFrame();
            mainFrame.setVisible(true);
        });
    }
}