import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import java.util.Base64;

public class RSASignature {

    private final KeyPair keyPair;
    private final Cipher cipher;

    // Construtor que inicializa o gerador de chaves e a cifra RSA
    public RSASignature(int keySize) throws NoSuchAlgorithmException, NoSuchPaddingException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        this.keyPair = keyGen.generateKeyPair();
        this.cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    // Geração de hash SHA-3
    private byte[] generateSHA3Hash(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return digest.digest(input);
    }

    // Cifração usando RSA com OAEP
    public String encrypt(String message) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedMessage = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    // Decifração usando RSA com OAEP
    public String decrypt(String encryptedMessage) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedMessage = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    // Assinatura da mensagem
    public String sign(String message) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(keyPair.getPrivate());
        privateSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // Verificação da assinatura
    public boolean verify(String message, String signature) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(keyPair.getPublic());
        publicSignature.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return publicSignature.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        RSASignature rsa = new RSASignature(2048);

        String message = "Esta é uma mensagem confidencial.";

        // Cifrar a mensagem
        String encryptedMessage = rsa.encrypt(message);
        System.out.println("Mensagem cifrada: " + encryptedMessage);

        // Decifrar a mensagem
        String decryptedMessage = rsa.decrypt(encryptedMessage);
        System.out.println("Mensagem decifrada: " + decryptedMessage);

        // Assinar a mensagem
        String signature = rsa.sign(message);
        System.out.println("Assinatura: " + signature);

        // Verificar a assinatura
        boolean isVerified = rsa.verify(message, signature);
        System.out.println("Assinatura verificada: " + isVerified);
    }
}
