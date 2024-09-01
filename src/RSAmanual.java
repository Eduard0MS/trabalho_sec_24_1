import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAmanual {

    private final BigInteger n;
    private final BigInteger e;
    private final BigInteger d;

    // Construtor para gerar chaves RSA de 1024 bits
    public RSAmanual(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.valueOf(65537); // Valor comum para e
        d = e.modInverse(phi);
    }

    // Cifrar uma mensagem usando a chave pública
    public byte[] encrypt(byte[] message) {
        BigInteger messageInt = new BigInteger(1, message);
        BigInteger cipherInt = messageInt.modPow(e, n);
        return cipherInt.toByteArray();
    }

    // Decifrar uma mensagem usando a chave privada
    public byte[] decrypt(byte[] cipher) {
        BigInteger cipherInt = new BigInteger(1, cipher);
        BigInteger messageInt = cipherInt.modPow(d, n);
        return messageInt.toByteArray();
    }

    // Assinatura digital usando chave privada
    public byte[] sign(byte[] message) {
        BigInteger hash = new BigInteger(1, message);  // Considerando que a mensagem já está hasheada
        BigInteger signature = hash.modPow(d, n);
        return signature.toByteArray();
    }

    // Verificação da assinatura usando chave pública
    public boolean verify(byte[] message, byte[] signature) {
        BigInteger hash = new BigInteger(1, message);  // Considerando que a mensagem já está hasheada
        BigInteger sigInt = new BigInteger(1, signature);
        BigInteger verifiedHash = sigInt.modPow(e, n);
        return hash.equals(verifiedHash);
    }

    public static void main(String[] args) {
        // Geração de chave RSA de 1024 bits
        RSAmanual RSAmanual = new RSAmanual(1024);

        // Exemplo de mensagem
        String message = "Este é um teste de RSA.";
        byte[] messageBytes = message.getBytes();

        // Cifrar a mensagem
        byte[] encryptedMessage = RSAmanual.encrypt(messageBytes);
        System.out.println("Mensagem cifrada: " + new BigInteger(1, encryptedMessage).toString(16));

        // Decifrar a mensagem
        byte[] decryptedMessage = RSAmanual.decrypt(encryptedMessage);
        System.out.println("Mensagem decifrada: " + new String(decryptedMessage));

        // Assinar a mensagem
        byte[] signature = RSAmanual.sign(messageBytes);
        System.out.println("Assinatura: " + new BigInteger(1, signature).toString(16));

        // Verificar a assinatura
        boolean isVerified = RSAmanual.verify(messageBytes, signature);
        System.out.println("Assinatura verificada: " + isVerified);
    }
}
