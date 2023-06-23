package org.mryndina.task2;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

/**
 * This class represents a test scenario for a Secure Messaging Protocol using RSA encryption.
 *
 * @author mryndina
 */
public class Test2 {
    // Trust Center
    private static KeyPair trustKeyPair; // TRUST key pair

    // Key pairs and public keys for Alice, Bob, and Eva
    private static Map<String, KeyPair> keyPairs = new HashMap<>(); // Key pairs (private and public) for each participant
    private static Map<String, PublicKey> publicKeys = new HashMap<>(); // Public keys for each participant, approved by TRUST

    /**
     * The main method that executes the test scenario.
     *
     * @param args Command line arguments (not used).
     * @throws Exception If an exception occurs during the execution.
     */
    public static void main(String[] args) throws Exception {
        // Generate keys for TRUST
        trustKeyPair = generateKeyPair();

        // Generate keys and certificates for Alice, Bob, and Eva
        keyPairs.put("Alice", generateKeyPair());
        keyPairs.put("Bob", generateKeyPair());
        keyPairs.put("Eva", generateKeyPair());

        // Authenticate Alice, Bob, and Eva using TRUST
        if (authenticate("Alice", publicKeys.get("Alice")) &&
                authenticate("Bob", publicKeys.get("Bob")) &&
                authenticate("Eva", publicKeys.get("Eva"))) {
            System.out.println("All participants are authenticated by TRUST.");
        } else {
            System.out.println("Authentication failed.");
            return;
        }

        // Secure Messaging Protocol
        String sender = "Alice";
        String receiver = "Bob";
        String message = "Hello Bob! This is a secure message from Alice.";

        // Attacker (Eve) performs a Man-in-the-Middle attack
        String attacker = "Eve";

        // Alice generates the encrypted container using Bob's public key
        byte[] encryptedContainer = encryptMessage(message, publicKeys.get(receiver));

        // Eve intercepts the container and replaces the sender identifier with her own public key
        sendMessage(encryptedContainer, sender, attacker);

        // Bob decrypts the container and receives the message, but he believes it's from Eve
        String receivedMessage = decryptMessage(encryptedContainer, keyPairs.get(receiver).getPrivate());
        System.out.println("Received message by Bob (as Eve): " + receivedMessage);

        // Eve, acting as Bob, encrypts the message with Alice's public key
        byte[] confirmation = encryptMessage("Message received by Eve (pretending as Bob).", publicKeys.get(sender));

        // Eve sends the confirmation to Alice
        sendMessage(confirmation, attacker, sender);

        // Alice decrypts the confirmation and receives the message, but she believes it's from Bob
        String receivedConfirmation = decryptMessage(confirmation, keyPairs.get(sender).getPrivate());
        System.out.println("Received confirmation by Alice (from Eve pretending as Bob): " + receivedConfirmation);

        // Alice compares the received message with the initial message she sent to Bob
        if (message.equals(receivedMessage)) {
            System.out.println("Alice mistakenly believes that Bob received the message.");
        } else {
            System.out.println("Message delivery confirmation failed.");
        }
    }

    /**
     * Generates a key pair using the RSA algorithm.
     *
     * @return The generated key pair.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key length
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Authenticates the participant's public key using TRUST.
     *
     * @param participant The participant's name.
     * @param publicKey   The participant's public key.
     * @return True if the authentication is successful, false otherwise.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws SignatureException       If an error occurs during the signature process.
     * @throws InvalidKeyException      If the provided key is invalid.
     */
    private static boolean authenticate(String participant, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // Create a signature using TRUST's private key
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(trustKeyPair.getPrivate());
        signature.update(publicKey.getEncoded());
        byte[] signatureBytes = signature.sign();

        // Verify the signature using TRUST's public key
        signature.initVerify(trustKeyPair.getPublic());
        signature.update(publicKey.getEncoded());
        return signature.verify(signatureBytes);
    }

    /**
     * Encrypts the message using the provided public key.
     *
     * @param message    The message to encrypt.
     * @param publicKey  The public key for encryption.
     * @return The encrypted message.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws NoSuchPaddingException   If the padding scheme is not available.
     * @throws InvalidKeyException      If the provided key is invalid.
     * @throws IllegalBlockSizeException If an error occurs during the encryption process.
     * @throws BadPaddingException       If the padding is incorrect.
     */
    private static byte[] encryptMessage(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    /**
     * Decrypts the encrypted message using the provided private key.
     *
     * @param encryptedMessage The encrypted message to decrypt.
     * @param privateKey       The private key for decryption.
     * @return The decrypted message.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws NoSuchPaddingException   If the padding scheme is not available.
     * @throws InvalidKeyException      If the provided key is invalid.
     * @throws IllegalBlockSizeException If an error occurs during the decryption process.
     * @throws BadPaddingException       If the padding is incorrect.
     */
    private static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    /**
     * Sends a message from the sender to the receiver.
     *
     * @param message  The message to send.
     * @param sender   The sender's name.
     * @param receiver The receiver's name.
     */
    private static void sendMessage(byte[] message, String sender, String receiver) {
        System.out.println("Message sent from " + sender + " to " + receiver + ": " + new String(message));
    }
}
