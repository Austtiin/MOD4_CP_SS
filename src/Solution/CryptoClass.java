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
import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptoClass {

    private static final Logger LOGGER = Logger.getLogger(CryptoClass.class.getName());

    private static final String AES_ALGORITHM = "AES";
    private static final String BLOWFISH_ALGORITHM = "Blowfish";
    private static final String CHACHA_ALGORITHM = "ChaCha20";
    private static final byte[] AES_KEY = "PROFESSORZayass!".getBytes();
    private static final byte[] BLOWFISH_KEY = "ZayazzKey1234".getBytes();
    private static final byte[] CHACHA_KEY = "ZayazzKey1234ZayazzKey1234ZayazzKey12".getBytes(); // 32-byte key for ChaCha20
    private static final byte[] CHACHA_NONCE = "123456789012".getBytes(); // 12-byte nonce for ChaCha20

    private static final String DATA_FOLDER = "src/data";

    public void processInput(String input, String algorithm) {
        String validatedInput = validateInput(input);

        String encrypted = encrypt(validatedInput, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + validatedInput);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

    public static List<String> listFiles() {
        try (Stream<Path> paths = Files.walk(Paths.get(DATA_FOLDER))) {
            return paths.filter(Files::isRegularFile)
                    .map(Path::getFileName)
                    .map(Path::toString)
                    .peek(System.out::println)
                    .collect(Collectors.toList());
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error listing files", ex);
            throw new RuntimeException("Error listing files: " + ex.getMessage());
        }
    }

    public static void updateFileWithEncryptedContent(String fileName, String newContent, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String validatedContent = validateInput(newContent);

        String encrypted = encrypt(validatedContent, algorithm);

        Files.write(Paths.get(filePath), encrypted.getBytes());
    }

    public static void updateFileWithDecryptedContent(String fileName, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String content = new String(Files.readAllBytes(Paths.get(filePath)));
        String decrypted = decrypt(content, algorithm);
        Files.write(Paths.get(filePath), decrypted.getBytes());
    }

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
            LOGGER.log(Level.SEVERE, "Error during encryption", ex);
            throw new RuntimeException(ex);
        }
    }

    private static String decrypt(String data, String algorithm) {
        try {
            Cipher cipher;
            byte[] key;

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
            LOGGER.log(Level.SEVERE, "Error during decryption", ex);
            throw new RuntimeException(ex);
        }
    }

    private static String validateInput(String input) {
        return input.replaceAll("[^a-zA-Z0-9\\p{Punct}]", "");
    }
}