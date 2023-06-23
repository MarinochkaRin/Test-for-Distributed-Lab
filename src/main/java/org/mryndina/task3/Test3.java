package org.mryndina.task3;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * This class implements a secure messaging protocol using public-key cryptography and digital signatures.
 *
 * @author mryndina
 */
public class Test3 {
    // Certification Authority
    private static KeyPair trustKeyPair; // TRUST key pair

    // Key pairs and certificates for Alice, Bob, and Eva
    private static Map<String, KeyPair> keyPairs = new HashMap<>(); // Key pairs (private and public) for each participant
    private static Map<String, PublicKey> publicKeys = new HashMap<>(); // Public keys for each participant, certified by TRUST

    /**
     * The main method demonstrating the secure messaging protocol.
     *
     * @param args command line arguments
     * @throws Exception if an exception occurs during the execution
     */
    public static void main(String[] args) throws Exception {
        // Generate keys for TRUST
        trustKeyPair = generateKeyPair();

        // Generate keys and certificates for Alice, Bob, and Eva
        keyPairs.put("Alice", generateKeyPair());
        keyPairs.put("Bob", generateKeyPair());
        keyPairs.put("Eva", generateKeyPair());

        // Certify the public keys of Alice, Bob, and Eva with TRUST
        publicKeys.put("Alice", keyPairs.get("Alice").getPublic());
        publicKeys.put("Bob", keyPairs.get("Bob").getPublic());
        publicKeys.put("Eva", keyPairs.get("Eva").getPublic());

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

        // Alice generates the encrypted container using Bob's public key
        byte[] encryptedContainer = encryptMessage(message, publicKeys.get(receiver));

        // Alice signs the encrypted container with her private key
        byte[] signature = signMessage(encryptedContainer, keyPairs.get(sender).getPrivate());

        // Alice transfers the container and the signature to Bob and attaches her PKA as the sender identifier
        sendMessage(encryptedContainer, signature, sender, receiver);

        // Bob verifies the signature using Alice's public key
        if (verifySignature(encryptedContainer, signature, publicKeys.get(sender))) {
            System.out.println("Signature verification passed.");
        } else {
            System.out.println("Signature verification failed.");
            return;
        }

        // Bob decrypts the container and receives the message
        String receivedMessage = decryptMessage(encryptedContainer, keyPairs.get(receiver).getPrivate());
        System.out.println("Received message by Bob: " + receivedMessage);

        // As a delivery confirmation, Bob encrypts the message with Alice's public key
        byte[] confirmation = encryptMessage("Message received by Bob.", publicKeys.get(sender));

        // Bob signs the confirmation with his private key
        byte[] confirmationSignature = signMessage(confirmation, keyPairs.get(receiver).getPrivate());

        // Bob sends the confirmation and the signature to Alice
        sendMessage(confirmation, confirmationSignature, receiver, sender);

        // Alice verifies the signature using Bob's public key
        if (verifySignature(confirmation, confirmationSignature, publicKeys.get(receiver))) {
            System.out.println("Confirmation signature verification passed.");
        } else {
            System.out.println("Confirmation signature verification failed.");
            return;
        }

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
     * @param participant the participant to be authenticated
     * @param publicKey   the public key of the participant
     * @return true if the authentication is successful, false otherwise
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws SignatureException       if an error occurs during the signature process
     * @throws InvalidKeyException      if the key is invalid
     */
    private static boolean authenticate(String participant, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // Create a signature using the private key of TRUST
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(trustKeyPair.getPrivate());
        signature.update(publicKey.getEncoded());
        byte[] signatureBytes = signature.sign();

        // Verify the signature using the public key of TRUST
        signature.initVerify(trustKeyPair.getPublic());
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
        Cipher cipher = Cipher.getInstance("RSA");
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
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    /**
     * Signs a message using the specified private key.
     *
     * @param message     the message to be signed
     * @param privateKey  the private key used for signing
     * @return the digital signature
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws SignatureException       if an error occurs during the signature process
     */
    private static byte[] signMessage(byte[] message, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    /**
     * Verifies the digital signature of a message using the specified public key.
     *
     * @param message       the message to be verified
     * @param signature     the digital signature
     * @param publicKey     the public key used for verification
     * @return true if the signature is valid, false otherwise
     * @throws NoSuchAlgorithmException if the RSA algorithm is not available
     * @throws InvalidKeyException      if the key is invalid
     * @throws SignatureException       if an error occurs during the signature verification process
     */
    private static boolean verifySignature(byte[] message, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(signature);
    }

    /**
     * Sends a message from the sender to the receiver.
     *
     * @param message    the message to be sent
     * @param signature  the digital signature
     * @param sender     the sender of the message
     * @param receiver   the receiver of the message
     */
    private static void sendMessage(byte[] message, byte[] signature, String sender, String receiver) {
        System.out.println("Message sent from " + sender + " to " + receiver + ": " + new String(message));
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));
    }
}
