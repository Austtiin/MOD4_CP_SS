//Solution.CryptoClass.java
//This is the class that will handle the encryption and decryption of the input

//Austin Stephens
//Rasmussen University
//CEN4071C
//Professor Zayaz
//08/28/2024

package Solution;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CryptoClass {

    // Keys and algorithms for encryption
    private static final String AES_ALGORITHM = "AES";
    private static final String BLOWFISH_ALGORITHM = "Blowfish";
    private static final String CHACHA_ALGORITHM = "ChaCha20";
    private static final byte[] AES_KEY = "PROFESSORZayass!".getBytes();
    private static final byte[] BLOWFISH_KEY = "ZayazzKey1234".getBytes();
    private static final byte[] CHACHA_KEY = "ZayazzKey1234ZayazzKey1234Zayazz".getBytes(); // 32-byte key for ChaCha20
    private static final byte[] CHACHA_NONCE = "123456789012".getBytes(); // 12-byte nonce for ChaCha20

    // Folder where data files are stored
    private static final String DATA_FOLDER = "src/data";


    //This method will process the file and encrypt and decrypt the content
    //It will take in the file name and the algorithm to use
    public static void processFile(String fileName, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String content = new String(Files.readAllBytes(Paths.get(filePath)));

        String encrypted = encrypt(content, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + content);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }



    //This method will process the input and encrypt and decrypt the content
    //It will take in the input and the algorithm to use
    public void processInput(String input, String algorithm) throws Exception {
        String validatedInput = validateInput(input);

        String encrypted = encrypt(validatedInput, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + validatedInput);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }



    //This method will list the files in the data folder
    //It will return a list of the files
    public static List<String> listFiles() throws Exception {
        try (Stream<Path> paths = Files.walk(Paths.get(DATA_FOLDER))) {
            return paths.filter(Files::isRegularFile)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .peek(System.out::println)
                    .collect(Collectors.toList());
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException("Error listing files: " + ex.getMessage());
        }
    }


    //This method will update the file with the encrypted content
    //It will take in the file name, the new content, and the algorithm to use
    public static void updateFileWithEncryptedContent(String fileName, String newContent, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String validatedContent = validateInput(newContent);

        String encrypted = encrypt(validatedContent, algorithm);

        Files.write(Paths.get(filePath), encrypted.getBytes());
    }


    //This method will update the file with the decrypted content
    //It will take in the file name and the algorithm to use
    public static void updateFileWithDecryptedContent(String fileName, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String content = new String(Files.readAllBytes(Paths.get(filePath)));
        String decrypted = decrypt(content, algorithm);
        Files.write(Paths.get(filePath), decrypted.getBytes());
    }


    //This method will encrypt the input
    //It will take in the data and the algorithm to use
    private static String encrypt(String data, String algorithm) {
        try {
            Cipher cipher;
            byte[] key;

            if (algorithm.equals(CHACHA_ALGORITHM)) {
                cipher = Cipher.getInstance("ChaCha20");
                key = CHACHA_KEY;
                ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(CHACHA_NONCE, 0);
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), paramSpec);
            } else {
                cipher = Cipher.getInstance(algorithm);
                key = algorithm.equals(AES_ALGORITHM) ? AES_KEY : BLOWFISH_KEY;
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm));
            }

            return "encrypted_" + Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
    }


    //This method will decrypt the input
    //It will take in the data and the algorithm to use
    private static String decrypt(String data, String algorithm) {
        try {
            Cipher cipher;
            byte[] key;

//********added ChaCha20 algorithm here, just did if else statement to check if the algorithm is ChaCha20

            if (algorithm.equals(CHACHA_ALGORITHM)) {
                cipher = Cipher.getInstance("ChaCha20");
                key = CHACHA_KEY;
                ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(CHACHA_NONCE, 0);
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), paramSpec);
            } else {
                cipher = Cipher.getInstance(algorithm);
                key = algorithm.equals(AES_ALGORITHM) ? AES_KEY : BLOWFISH_KEY;
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));
            }

            return new String(cipher.doFinal(Base64.getDecoder().decode(data.replace("encrypted_", ""))));
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
    }


    //This method will validate the input
    //It will take in the input and return the validated input
    private static String validateInput(String input) {
        return input.replaceAll("[^a-zA-Z0-9\\p{Punct}]", "");
    }
}
