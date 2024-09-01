import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class RSAarquivo {

    private final BigInteger n;
    private final BigInteger e;
    private final BigInteger d;

    // Construtor para gerar chaves RSA de 1024 bits com teste de primalidade Miller-Rabin
    public RSAarquivo(int bitLength) throws IOException {
        SecureRandom random = new SecureRandom();
        BigInteger p = generatePrime(bitLength / 2, random);
        BigInteger q = generatePrime(bitLength / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.valueOf(65537); // Valor comum para e
        d = e.modInverse(phi);

        System.out.println("Chaves RSA geradas:");
        System.out.println("n: " + n.toString(16));
        System.out.println("e: " + e.toString(16));
        System.out.println("d: " + d.toString(16));

        // Salvar as chaves em arquivos
        saveKeyToFile("public.key", n, e);
        saveKeyToFile("private.key", n, d);
    }

    // Método para salvar chaves em arquivos
    private void saveKeyToFile(String filename, BigInteger n, BigInteger exponent) throws IOException {
        String keyContent = "n: " + n.toString(16) + "\n" + "exponent: " + exponent.toString(16);
        Files.writeString(Paths.get(filename), keyContent);
        System.out.println("Chave salva em: " + filename);
    }

    // Metodo para gerar um número primo usando o teste de primalidade Miller-Rabin
    private BigInteger generatePrime(int bitLength, SecureRandom random) {
        BigInteger prime;
        do {
            prime = new BigInteger(bitLength, random);
        } while (!prime.isProbablePrime(100)); // 100 iterações de Miller-Rabin
        return prime;
    }

    // Implementação do OAEP
    private byte[] oaepPad(byte[] data, int length, SecureRandom random) {
        byte[] padded = new byte[length];
        byte[] seed = new byte[20]; // Tamanho do hash SHA-1
        random.nextBytes(seed);
        byte[] db = new byte[length - seed.length];

        // Padding com zeros
        System.arraycopy(data, 0, db, db.length - data.length, data.length);

        // Aplicando máscara de dados (MGF1)
        byte[] dbMask = mgf1(seed, db.length);
        for (int i = 0; i < db.length; i++) {
            db[i] ^= dbMask[i];
        }

        // Aplicando máscara de semente (MGF1)
        byte[] seedMask = mgf1(db, seed.length);
        for (int i = 0; i < seed.length; i++) {
            seed[i] ^= seedMask[i];
        }

        // Construindo a mensagem final
        System.arraycopy(seed, 0, padded, 0, seed.length);
        System.arraycopy(db, 0, padded, seed.length, db.length);

        return padded;
    }

    private byte[] oaepUnpad(byte[] padded) {
        int seedLength = 20; // Tamanho do hash SHA-1
        byte[] seed = Arrays.copyOfRange(padded, 0, seedLength);
        byte[] db = Arrays.copyOfRange(padded, seedLength, padded.length);

        // Aplicando máscara de semente
        byte[] seedMask = mgf1(db, seedLength);
        for (int i = 0; i < seed.length; i++) {
            seed[i] ^= seedMask[i];
        }

        // Aplicando máscara de dados
        byte[] dbMask = mgf1(seed, db.length);
        for (int i = 0; i < db.length; i++) {
            db[i] ^= dbMask[i];
        }

        // Extraindo os dados reais (removendo o padding)
        int index = 0;
        while (index < db.length && db[index] == 0) {
            index++;
        }

        return Arrays.copyOfRange(db, index, db.length);
    }

    private byte[] mgf1(byte[] seed, int length) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] output = new byte[length];
            byte[] counter = new byte[4];
            for (int i = 0; i < (length + sha1.getDigestLength() - 1) / sha1.getDigestLength(); i++) {
                counter[3] = (byte) i;
                sha1.update(seed);
                sha1.update(counter);
                byte[] hash = sha1.digest();
                System.arraycopy(hash, 0, output, i * sha1.getDigestLength(),
                        Math.min(sha1.getDigestLength(), length - i * sha1.getDigestLength()));
            }
            return output;
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    // Assinatura digital usando chave privada
    public String sign(File file) throws NoSuchAlgorithmException, IOException {
        byte[] fileBytes = Files.readAllBytes(file.toPath());

        // Calcular o hash SHA-3 do arquivo
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        byte[] hash = sha3.digest(fileBytes);
        System.out.println("Hash calculado (antes do padding): " + Base64.getEncoder().encodeToString(hash));

        // Assinar o hash
        BigInteger hashInt = new BigInteger(1, hash);
        System.out.println("Hash como BigInteger antes de assinatura: " + hashInt.toString(16));
        byte[] paddedHash = oaepPad(hashInt.toByteArray(), n.bitLength() / 8, new SecureRandom());
        System.out.println("Hash após o padding OAEP: " + Base64.getEncoder().encodeToString(paddedHash));
        BigInteger signature = new BigInteger(1, paddedHash).modPow(d, n);

        // Codificar o hash e a assinatura em Base64 para armazenamento
        String hashBase64 = Base64.getEncoder().encodeToString(hash);
        String signatureBase64 = Base64.getEncoder().encodeToString(signature.toByteArray());

        // Salvar a assinatura em um arquivo
        saveSignatureToFile("signature.txt", hashBase64, signatureBase64);

        // Salvar hash e assinatura em um formato próprio
        return hashBase64 + ":" + signatureBase64;
    }

    // Método para salvar a assinatura em um arquivo
    private void saveSignatureToFile(String filename, String hashBase64, String signatureBase64) throws IOException {
        String signatureContent = "Hash Base64: " + hashBase64 + "\n" + "Assinatura Base64: " + signatureBase64;
        Files.writeString(Paths.get(filename), signatureContent);
        System.out.println("Assinatura salva em: " + filename);
    }

    // Verificação de assinatura usando chave pública
    public boolean verify(File file, String signedData) throws NoSuchAlgorithmException, IOException {
        System.out.println("Iniciando processo de verificação...");

        // 1. Parsing do documento assinado e decifração da mensagem (de acordo com a formatação usada, no caso BASE64)
        System.out.println("Parsing do documento assinado...");
        String[] parts = signedData.split(":");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Dados assinados em formato incorreto");
        }

        // Extrair hash e assinatura do arquivo
        String hashBase64 = parts[0];
        String signatureBase64 = parts[1];

        System.out.println("Hash Base64 extraído: " + hashBase64);
        System.out.println("Assinatura Base64 extraída: " + signatureBase64);

        // Decodificar o hash e a assinatura de Base64
        byte[] hashOriginal = Base64.getDecoder().decode(hashBase64);
        System.out.println("Hash original decodificado de Base64: " + Base64.getEncoder().encodeToString(hashOriginal));
        BigInteger signature = new BigInteger(1, Base64.getDecoder().decode(signatureBase64));

        // 2. Decifração da assinatura (decifração do hash)
        System.out.println("Decifrando a assinatura...");
        byte[] paddedHash = signature.modPow(e, n).toByteArray();
        byte[] hashDeciphered = oaepUnpad(paddedHash);
        System.out.println("Hash decifrado com a chave pública: " + Base64.getEncoder().encodeToString(hashDeciphered));

        // 3. Verificação (cálculo e comparação do hash do arquivo)
        System.out.println("Calculando o hash do arquivo novamente...");
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
        byte[] hashNew = sha3.digest(fileBytes);
        System.out.println("Hash recalculado do arquivo: " + Base64.getEncoder().encodeToString(hashNew));

        // Verificar se os hashes coincidem
        boolean hashesMatch = MessageDigest.isEqual(hashOriginal, hashNew);
        boolean signaturesMatch = MessageDigest.isEqual(hashOriginal, hashDeciphered);

        System.out.println("O hash do documento corresponde ao hash decifrado? " + signaturesMatch);
        System.out.println("O hash do documento corresponde ao hash recalculado? " + hashesMatch);

        // Salvar o log de verificação
        saveVerificationLog("verification_log.txt", hashOriginal, hashDeciphered, hashNew, signaturesMatch, hashesMatch);

        return hashesMatch && signaturesMatch;
    }

    // Método para salvar o log de verificação em um arquivo
    private void saveVerificationLog(String filename, byte[] hashOriginal, byte[] hashDeciphered, byte[] hashNew, boolean signaturesMatch, boolean hashesMatch) throws IOException {
        String logContent = "Hash original decodificado de Base64: " + Base64.getEncoder().encodeToString(hashOriginal) + "\n" +
                "Hash decifrado com a chave pública: " + Base64.getEncoder().encodeToString(hashDeciphered) + "\n" +
                "Hash recalculado do arquivo: " + Base64.getEncoder().encodeToString(hashNew) + "\n" +
                "O hash do documento corresponde ao hash decifrado? " + signaturesMatch + "\n" +
                "O hash do documento corresponde ao hash recalculado? " + hashesMatch;
        Files.writeString(Paths.get(filename), logContent);
        System.out.println("Log de verificação salvo em: " + filename);
    }

    public static void main(String[] args) throws Exception {
        // Geração de chave RSA de 1024 bits
        RSAarquivo rsaArquivo = new RSAarquivo(1024);

        // Exemplo de arquivo
        File file = new File("D:\IntelliJ\projetos_unb\PROJETO_SEGURAN\src\selfie.jpg");

        // Assinar o arquivo
        String signedData = rsaArquivo.sign(file);
        System.out.println("Dados assinados: " + signedData);

        // Verificar a assinatura
        boolean isVerified = rsaArquivo.verify(file, signedData);
        System.out.println("Assinatura verificada: " + isVerified);
    }
}
