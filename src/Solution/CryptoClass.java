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
import java.nio.file.Paths;
import java.nio.file.Path;
import java.util.Base64;
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
    private static final byte[] CHACHA_KEY = "ProfessorZayas!ZayasProfessorPRO".getBytes();
    private static final byte[] CHACHA_NONCE = "12345678".getBytes();



    private static final String DATA_FOLDER = "src/data";

    public static void processFile(String fileName, String algorithm) throws Exception {
        String filePath = Paths.get(DATA_FOLDER, fileName).toString();
        String content = new String(Files.readAllBytes(Paths.get(filePath)));

        String encrypted = encrypt(content, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + content);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

    public void processInput(String input, String algorithm) throws Exception {
        String validatedInput = validateInput(input);

        String encrypted = encrypt(validatedInput, algorithm);
        String decrypted = decrypt(encrypted, algorithm);

        System.out.println("Original: " + validatedInput);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

    public static List<String> listFiles() throws Exception {
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
            if (CHACHA_ALGORITHM.equals(algorithm)) {
                ChaChaEngine engine = new ChaChaEngine(20); // 20 rounds for ChaCha20
                ParametersWithIV paramSpec = new ParametersWithIV(new KeyParameter(CHACHA_KEY), CHACHA_NONCE);
                engine.init(true, paramSpec);
                byte[] output = new byte[data.length()];
                engine.processBytes(data.getBytes(), 0, data.length(), output, 0);
                LOGGER.info("ChaCha20 encryption successful. Data length: " + data.length());
                return "encrypted_" + Base64.getEncoder().encodeToString(output);
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

    private static String decrypt(String data, String algorithm) {
        try {
            if (CHACHA_ALGORITHM.equals(algorithm)) {
                ChaChaEngine engine = new ChaChaEngine(20);
                ParametersWithIV paramSpec = new ParametersWithIV(new KeyParameter(CHACHA_KEY), CHACHA_NONCE);
                engine.init(false, paramSpec);
                byte[] decodedData = Base64.getDecoder().decode(data.replace("encrypted_", ""));
                byte[] output = new byte[decodedData.length];
                engine.processBytes(decodedData, 0, decodedData.length, output, 0);
                LOGGER.info("ChaCha20 decryption successful. Encrypted data length: " + data.length());
                return new String(output);
            } else {
                Cipher cipher = Cipher.getInstance(algorithm);
                byte[] key = AES_ALGORITHM.equals(algorithm) ? AES_KEY : BLOWFISH_KEY;
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm));
                LOGGER.info("Decryption successful. Encrypted data length: " + data.length());
                return new String(cipher.doFinal(Base64.getDecoder().decode(data.replace("encrypted_", ""))));
            }
        } catch (Exception ex) {
            LOGGER.log(Level.SEVERE, "Error during decryption with algorithm: " + algorithm, ex);
            throw new RuntimeException(ex);
        }
    }


    private static String validateInput(String input) {
        return input.replaceAll("[^a-zA-Z0-9\\p{Punct}]", "");
    }
}
