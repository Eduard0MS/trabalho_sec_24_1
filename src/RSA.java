import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Random;

public class RSA {

    private final BigInteger n;
    private final BigInteger d;
    private BigInteger e;

    // Geração de chaves RSA
    public RSA(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength, random);
        BigInteger q = BigInteger.probablePrime(bitLength, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitLength / 2, random);

        while (phi.gcd(e).intValue() > 1) {
            e = e.add(BigInteger.TWO);
        }
        d = e.modInverse(phi);
    }

    // Cifração usando RSA-OAEP
    public String encrypt(String message) throws Exception {
        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] paddedMsg = oaepPad(msgBytes, n.bitLength() / 8);
        BigInteger m = new BigInteger(1, paddedMsg);
        BigInteger c = m.modPow(e, n);
        return Base64.getEncoder().encodeToString(c.toByteArray());
    }

    // Decifração usando RSA-OAEP
    public String decrypt(String encryptedMessage) throws Exception {
        BigInteger c = new BigInteger(1, Base64.getDecoder().decode(encryptedMessage));
        BigInteger m = c.modPow(d, n);
        byte[] msgBytes = oaepUnpad(m.toByteArray(), n.bitLength() / 8);
        return new String(msgBytes, StandardCharsets.UTF_8);
    }

    // Assinatura da mensagem
    public String sign(String message) throws Exception {
        byte[] hash = sha3Hash(message.getBytes(StandardCharsets.UTF_8));
        BigInteger hashInt = new BigInteger(1, hash);
        BigInteger signature = hashInt.modPow(d, n);
        return Base64.getEncoder().encodeToString(signature.toByteArray());
    }

    // Verificação da assinatura
    public boolean verify(String message, String signature) throws Exception {
        byte[] hash = sha3Hash(message.getBytes(StandardCharsets.UTF_8));
        BigInteger hashInt = new BigInteger(1, hash);

        BigInteger sigInt = new BigInteger(1, Base64.getDecoder().decode(signature));
        BigInteger decryptedHash = sigInt.modPow(e, n);

        return hashInt.equals(decryptedHash);
    }

    // Função de hash SHA-3
    private byte[] sha3Hash(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        return digest.digest(input);
    }

    // OAEP padding (simplificado)
    private byte[] oaepPad(byte[] data, int length) {
        byte[] padded = new byte[length];
        System.arraycopy(data, 0, padded, 0, data.length);
        // Adicionando padding simples para exemplo
        for (int i = data.length; i < length; i++) {
            padded[i] = 0x00;
        }
        return padded;
    }

    // OAEP unpadding (simplificado)
    private byte[] oaepUnpad(byte[] data, int length) {
        int i = 0;
        while (i < data.length && data[i] != 0x00) {
            i++;
        }
        byte[] unpadded = new byte[i];
        System.arraycopy(data, 0, unpadded, 0, i);
        return unpadded;
    }

    public static void main(String[] args) throws Exception {
        RSA rsa = new RSA(1024);

        String message = "Esta é uma mensagem secreta.";

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
