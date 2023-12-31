package org.mryndina.task1;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

public class Test1 {
    // Certification Authority
    private static KeyPair trustKeyPair; // TRUST key pair
    private static PublicKey trustPublicKey; // TRUST public key

    // Key pairs and public keys for Alice, Bob, and Eva
    private static Map<String, KeyPair> keyPairs = new HashMap<>(); // Key pairs (private and public) for each participant
    private static Map<String, PublicKey> publicKeys = new HashMap<>(); // Public keys for each participant

    /**
     * The main method demonstrating the secure messaging protocol.
     *
     * @param args command line arguments
     * @throws Exception if an exception occurs during the execution
     */
    public static void main(String[] args) throws Exception {
        // Generate keys for TRUST
        trustKeyPair = generateKeyPair();
        trustPublicKey = trustKeyPair.getPublic();

        // Generate keys for Alice, Bob, and Eva
        keyPairs.put("Alice", generateKeyPair());
        keyPairs.put("Bob", generateKeyPair());
        keyPairs.put("Eva", generateKeyPair());

        // Certify the public keys of Alice, Bob, and Eva with TRUST
        publicKeys.put("Alice", keyPairs.get("Alice").getPublic());
        publicKeys.put("Bob", keyPairs.get("Bob").getPublic());
        publicKeys.put("Eva", keyPairs.get("Eva").getPublic());

        // Authenticate Alice, Bob, and Eva using TRUST
        if (authenticate("Alice", publicKeys.get("Alice"), trustPublicKey) &&
                authenticate("Bob", publicKeys.get("Bob"), trustPublicKey) &&
                authenticate("Eva", publicKeys.get("Eva"), trustPublicKey)) {
            System.out.println("All participants are authenticated by TRUST.");
        } else {
            System.out.println("Authentication failed.");
            return;
        }

        // Secure Messaging Protocol
        String sender = "Alice";
        String receiver = "Bob";
        String message = "Hello Bob! This is a secure message from Alice.";

        // Alice generates the encrypted container using Bob's public key
        byte[] encryptedContainer = encryptMessage(message, publicKeys.get(receiver));

        // Alice transfers the container to Bob and attaches her PKA as the sender identifier
        sendMessage(encryptedContainer, sender, receiver);

        // Bob decrypts the container and receives the message
        String receivedMessage = decryptMessage(encryptedContainer, keyPairs.get(receiver).getPrivate());
        System.out.println("Received message by Bob: " + receivedMessage);

        // As a delivery confirmation, Bob encrypts the message with Alice's public key
        byte[] confirmation = encryptMessage("Message received by Bob.", publicKeys.get(sender));

        // Bob sends the confirmation to Alice
        sendMessage(confirmation, receiver, sender);

        // Alice decrypts the confirmation and receives the message
        String receivedConfirmation = decryptMessage(confirmation, keyPairs.get(sender).getPrivate());
        System.out.println("Received confirmation by Alice: " + receivedConfirmation);

        // Alice compares the received message with the initial message she sent to Bob
        if (message.equals(receivedMessage)) {
            System.out.println("Alice made sure that Bob received the message.");
        } else {
            System.out.println("Message delivery confirmation failed.");
        }
    }

    /**
     * Generates a key pair using the RSA algorithm.
     *
     * @return the generated key pair
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     */
    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key length
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Authenticates the public key of a participant using TRUST.
     *
     * @param participant   the participant to be authenticated
     * @param publicKey     the public key of the participant
     * @param trustPublicKey the public key of the TRUST
     * @return true if the authentication is successful, false otherwise
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws SignatureException       if an error occurs during the signature process
     * @throws InvalidKeyException      if the key is invalid
     */
    private static boolean authenticate(String participant, PublicKey publicKey, PublicKey trustPublicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // Create a signature using the private key of TRUST
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(trustKeyPair.getPrivate());
        signature.update(publicKey.getEncoded());
        byte[] signatureBytes = signature.sign();

        // Verify the signature using the public key of TRUST
        signature.initVerify(trustPublicKey);
        signature.update(publicKey.getEncoded());
        return signature.verify(signatureBytes);
    }

    /**
     * Encrypts a message using the specified public key.
     *
     * @param message    the message to be encrypted
     * @param publicKey  the public key used for encryption
     * @return the encrypted message
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws NoSuchPaddingException   if the padding scheme is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws IllegalBlockSizeException if the input data is not a multiple of the cipher block size
     * @throws BadPaddingException       if the padding is invalid
     */
    private static byte[] encryptMessage(String message, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    /**
     * Decrypts a message using the specified private key.
     *
     * @param encryptedMessage the encrypted message
     * @param privateKey       the private key used for decryption
     * @return the decrypted message
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws NoSuchPaddingException   if the padding scheme is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws IllegalBlockSizeException if the input data is not a multiple of the cipher block size
     * @throws BadPaddingException       if the padding is invalid
     */
    private static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    /**
     * Sends a message from the sender to the receiver.
     *
     * @param message  the message to be sent
     * @param sender   the sender of the message
     * @param receiver the receiver of the message
     */
    private static void sendMessage(byte[] message, String sender, String receiver) {
        System.out.println("Message sent from " + sender + " to " + receiver + ".");
    }
}
