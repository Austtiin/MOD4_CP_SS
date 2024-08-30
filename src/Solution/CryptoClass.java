//Solution.CryptoClass.java
//This is the class that will handle the encryption and decryption of the input

//Austin Stephens
//Rasmussen University
//CEN4071C
//Professor Zayaz
//08/28/2024

package Solution;

import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CryptoClass {

    //new logger for the class to display any errors
    private static final Logger LOGGER = Logger.getLogger(CryptoClass.class.getName());


    //KEYS
    //
    private static final String AES_ALGORITHM = "AES";
    private static final String BLOWFISH_ALGORITHM = "Blowfish";
    private static final String CHACHA_ALGORITHM = "ChaCha20";
    private static final byte[] AES_KEY = "PROFESSORZayass!".getBytes();
    private static final byte[] BLOWFISH_KEY = "ZayazzKey1234".getBytes();
    private static final byte[] CHACHA_KEY = "ProfessorZayas!ZayasProfessorPRO".getBytes();
    private static final byte[] CHACHA_NONCE = "12345678".getBytes();

    //DATA FOLDER
    private static final String DATA_FOLDER = "src/data";


    //process file method
    //This method will take in a file name and an algorithm
    public static void processFile(String fileName, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String content = new String(Files.readAllBytes(Paths.get(filePath)));

        String encrypted = encrypt(content, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + content);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

    //list files method
    //This method will list all the files in the data folder
    public static List<String> listFiles() throws Exception {
        try (Stream<Path> paths = Files.walk(Paths.get(DATA_FOLDER))) {

            //filter the paths to only include regular files
            return paths.filter(Files::isRegularFile)
                    //map the paths to the file name
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .peek(System.out::println)
                    .collect(Collectors.toList());
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error listing files", ex);
            throw new RuntimeException("Error listing files: " + ex.getMessage());
        }
    }

    //update file with encrypted content method
    //This method will take in a file name, new content, and an algorithm
    public static void updateFileWithEncryptedContent(String fileName, String newContent, String algorithm) throws Exception {

        //get the file path to the data folder
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();

        //validate the input
        String validatedContent = validateInput(newContent);

        //encrypt the validated content
        String encrypted = encrypt(validatedContent, algorithm);

        //write the encrypted content to the file
        Files.write(Paths.get(filePath), encrypted.getBytes());
    }

    //update file with decrypted content method
    //This method will take in a file name and an algorithm
    public static void updateFileWithDecryptedContent(String fileName, String algorithm) throws Exception {

        //get the file path to the data folder
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();

        //read the content of the file
        String content = new String(Files.readAllBytes(Paths.get(filePath)));

        //decrypt the content
        String decrypted = decrypt(content, algorithm);

        //then write the decrypted content to the file
        Files.write(Paths.get(filePath), decrypted.getBytes());
    }

    //encrypt method
    //This method will take in a string data and an algorithm
    private static String encrypt(String data, String algorithm) {
        try {

            //added chacha algorithm here, simple IF statement to check if the algorithm is chacha
            if (CHACHA_ALGORITHM.equals(algorithm)) {
                //new chacha engine then we pass the key and nonce to the engine
                ChaChaEngine engine = new ChaChaEngine(20);

                //nonce is a number used only once and we pass the key and nonce to the engine
                ParametersWithIV paramSpec = new ParametersWithIV(new KeyParameter(CHACHA_KEY), CHACHA_NONCE);

                //initialize the engine with the key and nonce
                //true is passed to the init method to encrypt
                engine.init(true, paramSpec);

                //encode the data and store it in a byte array
                byte[] output = new byte[data.length()];

                //process the bytes
                engine.processBytes(data.getBytes(), 0, data.length(), output, 0);

                //log the success of the encryption
                LOGGER.info("ChaCha20 encryption successful. Data length: " + data.length());
                return "encrypted_" + Base64.getEncoder().encodeToString(output);

                //else look for the other algorithms
            } else {
                Cipher cipher = Cipher.getInstance(algorithm);
                byte[] key = AES_ALGORITHM.equals(algorithm) ? AES_KEY : BLOWFISH_KEY;
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));
                LOGGER.info("Encryption successful. Data length: " + data.length());
                return "encrypted_" + Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error during encryption with algorithm: " + algorithm, ex);
            throw new RuntimeException(ex);
        }
    }

    //  decrypt method
    //This method will take in a string data and an algorithm
    private static String decrypt(String data, String algorithm) {
        try {
            //added chacha algorithm here, simple IF statement to check if the algorithm is chacha
            if (CHACHA_ALGORITHM.equals(algorithm)) {

                //new chacha engine then we pass the key and nonce to the engine
                //nonce is a number used only once
                ChaChaEngine engine = new ChaChaEngine(20);
                ParametersWithIV paramSpec = new ParametersWithIV(new KeyParameter(CHACHA_KEY), CHACHA_NONCE);

                //initialize the engine with the key and nonce
                //false is passed to the init method to decrypt
                engine.init(false, paramSpec);

                //decode the data and store it in a byte array
                byte[] decodedData = Base64.getDecoder().decode(data.replace("encrypted_", ""));
                byte[] output = new byte[decodedData.length];
                //process the bytes
                engine.processBytes(decodedData, 0, decodedData.length, output, 0);

                //log the success of the decryption
                LOGGER.info("ChaCha20 decryption successful. Encrypted data length: " + data.length());
                return new String(output);

                //else look for the other algorithms
            } else {
                //initialize the cipher with the algorithm
                Cipher cipher = Cipher.getInstance(algorithm);
                //check if the algorithm is AES or Blowfish
                byte[] key = AES_ALGORITHM.equals(algorithm) ? AES_KEY : BLOWFISH_KEY;

                //then initialize the cipher with the key and the algorithm
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));
                LOGGER.info("Decryption successful. Encrypted data length: " + data.length());
                return new String(cipher.doFinal(Base64.getDecoder().decode(data.replace("encrypted_", ""))));

            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error during decryption with algorithm: " + algorithm, ex);
            throw new RuntimeException(ex);
        }
    }

//validate input method
    private static String validateInput(String input) {

        return input.replaceAll("[^a-zA-Z0-9\\p{Punct}]", "");
    }

    //process input method
    //This method will take in a string input and an algorithm
    public void processInput(String input, String algorithm) throws Exception {
        String validatedInput = validateInput(input);

        String encrypted = encrypt(validatedInput, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + validatedInput);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
