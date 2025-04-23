/*  AESLgpdCompliantSecure.java
 *  Implementação de criptografia, guarda de chaves e ABAC em conformidade
 *  LGPD nível “10/10”.
 *
 *  Dependências Maven (exemplo):
 *  <dependency>
 *      <groupId>software.amazon.awssdk</groupId><artifactId>kms</artifactId><version>2.25.32</version>
 *  </dependency>
 *  <dependency>
 *      <groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.17.0</version>
 *  </dependency>
 */

package com.example.lgpd;

import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/* ---------- MODELOS AUXILIARES ---------- */

record WrappedKey(String cmkId, byte[] cipherKey) implements Serializable {}

/** Metadados serializados junto com o arquivo */
class ImageMetadata implements Serializable {
    String imageId = UUID.randomUUID().toString();
    String createdAt = LocalDateTime.now().toString();
    String lastAccessed = createdAt;
    String purpose;
    String owner;
    String retentionPeriod;          // ISO-8601
    String cmkId;                    // ARN/alias da CMK usada
    String wrappedDataKeyB64;        // chave de dados cifrada (Base64)
    String ivB64;                    // IV (Base64)

    // serialização simples = key=value;...
    byte[] toBytes() {
        return String.format(Locale.ROOT,
                "imageId=%s;createdAt=%s;lastAccessed=%s;purpose=%s;owner=%s;retention=%s;cmk=%s;dk=%s;iv=%s",
                imageId, createdAt, lastAccessed, purpose, owner, retentionPeriod,
                cmkId, wrappedDataKeyB64, ivB64)
                .getBytes(StandardCharsets.UTF_8);
    }

    static ImageMetadata fromBytes(byte[] bytes) {
        var md = new ImageMetadata();
        String[] parts = new String(bytes, StandardCharsets.UTF_8).split(";");
        for (String p : parts) {
            String[] kv = p.split("=", 2);
            if (kv.length != 2) continue;
            switch (kv[0]) {
                case "imageId"    -> md.imageId = kv[1];
                case "createdAt"  -> md.createdAt = kv[1];
                case "lastAccessed" -> md.lastAccessed = kv[1];
                case "purpose"    -> md.purpose = kv[1];
                case "owner"      -> md.owner = kv[1];
                case "retention"  -> md.retentionPeriod = kv[1];
                case "cmk"        -> md.cmkId = kv[1];
                case "dk"         -> md.wrappedDataKeyB64 = kv[1];
                case "iv"         -> md.ivB64 = kv[1];
            }
        }
        return md;
    }
}

/* ---------- REPOSITÓRIO DE CHAVES (AWS KMS) ---------- */
interface KeyRepository {
    WrappedKey wrap(SecretKey dataKey) throws Exception;
    SecretKey unwrap(WrappedKey wrapped) throws Exception;
}

/** Implementação real usando AWS KMS */
class AwsKmsRepository implements KeyRepository {
    private final KmsClient kms;
    private final String cmkId;

    AwsKmsRepository(String cmkId) {
        this.kms = KmsClient.builder()
                .region(Region.AWS_GLOBAL)        // ou Region.of("us-east-1")
                .build();
        this.cmkId = cmkId;
    }

    @Override
    public WrappedKey wrap(SecretKey dk) {
        var enc = kms.encrypt(EncryptRequest.builder()
                .keyId(cmkId)
                .plaintext(SdkBytes.fromByteArray(dk.getEncoded()))
                .build());
        return new WrappedKey(cmkId, enc.ciphertextBlob().asByteArray());
    }

    @Override
    public SecretKey unwrap(WrappedKey w) {
        var dec = kms.decrypt(DecryptRequest.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(w.cipherKey()))
                .build());
        return new SecretKeySpec(dec.plaintext().asByteArray(), "AES");
    }
}

/* ---------- ABAC (OPA via HTTP) ---------- */
interface AbacService {
    boolean allowed(String op, ImageMetadata md, String userId, Set<String> roles) throws Exception;
}

/** Consulta OPA Data API via HTTP POST */
class OpaAbacService implements AbacService {
    private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    private final URI uri;
    private static final ObjectMapper mapper = new ObjectMapper();

    OpaAbacService(String opaEndpoint) { this.uri = URI.create(opaEndpoint); }

    @Override
    public boolean allowed(String op, ImageMetadata md, String userId, Set<String> roles) throws Exception {
        Map<String, Object> input = Map.of(
                "op", op,
                "user", userId,
                "user_roles", roles,
                "owner", md.owner,
                "purpose", md.purpose
        );
        String body = mapper.writeValueAsString(Map.of("input", input));
        HttpRequest req = HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        Map<?, ?> result = mapper.readValue(resp.body(), Map.class);
        return Boolean.TRUE.equals(result.get("result"));
    }
}

/* ---------- AUDITORIA HASH-CADEIA ---------- */
class Audit {
    private static final MessageDigest DIGEST;
    private static byte[] lastHash = new byte[32];
    private static final PrintWriter out;

    static {
        try {
            DIGEST = MessageDigest.getInstance("SHA-256");
            out = new PrintWriter(new FileWriter("lgpd_audit.log", true), true);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static synchronized void log(String msg) {
        String line = LocalDateTime.now() + " | " + msg + " | "
                + Base64.getEncoder().encodeToString(lastHash);
        lastHash = DIGEST.digest(line.getBytes(StandardCharsets.UTF_8));
        out.println(line);
    }
}

/* ---------- CLASSE PRINCIPAL ---------- */
public class AESLgpdCompliantSecure {

    /* --- Constantes criptográficas --- */
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS  = 128;
    private static final int DATA_KEY_SIZE = 256;
    private static final SecureRandom RNG  = new SecureRandom();

    /* --- Serviços injetáveis (podem vir de DI/Spring) --- */
    private static final KeyRepository KEYS = new AwsKmsRepository("alias/lgpd-cmk");
    private static final AbacService   ABAC = new OpaAbacService("https://opa.mycorp.local/v1/data/lgpd/allow");

    /* --- API pública --- */

    public static byte[] encryptImage(byte[] img, String userId, Set<String> roles,
                                      String purpose, LocalDateTime retention) throws Exception {

        // Generate one-time data key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(DATA_KEY_SIZE, RNG);
        SecretKey dataKey = kg.generateKey();

        // Wrap with KMS
        WrappedKey wrapped = KEYS.wrap(dataKey);

        // IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        RNG.nextBytes(iv);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, dataKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        ImageMetadata md = new ImageMetadata();
        md.owner = userId;
        md.purpose = purpose;
        md.retentionPeriod = retention.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        md.cmkId = wrapped.cmkId();
        md.wrappedDataKeyB64 = Base64.getEncoder().encodeToString(wrapped.cipherKey());
        md.ivB64 = Base64.getEncoder().encodeToString(iv);

        byte[] aad = md.toBytes();
        c.updateAAD(aad);
        byte[] cipherText = c.doFinal(img);

        // Assemble: [4 bytes lenAAD][AAD][ciphertext]
        ByteBuffer buf = ByteBuffer.allocate(4 + aad.length + cipherText.length);
        buf.putInt(aad.length);
        buf.put(aad);
        buf.put(cipherText);

        Audit.log("ENCRYPT " + md.imageId + " by " + userId);
        zeroize(dataKey.getEncoded());
        return buf.array();
    }

    public static byte[] decryptImage(byte[] enc, String userId, Set<String> roles) throws Exception {
        ByteBuffer buf = ByteBuffer.wrap(enc);
        int len = buf.getInt();
        byte[] aad = new byte[len];
        buf.get(aad);
        ImageMetadata md = ImageMetadata.fromBytes(aad);

        // ABAC
        if (!ABAC.allowed("DECRYPT", md, userId, roles))
            throw new SecurityException("Access denied by ABAC");

        // Check retention
        if (LocalDateTime.now().isAfter(LocalDateTime.parse(md.retentionPeriod)))
            throw new SecurityException("Retention period expired");

        byte[] cipher = new byte[buf.remaining()];
        buf.get(cipher);

        // Unwrap data key
        WrappedKey w = new WrappedKey(md.cmkId, Base64.getDecoder().decode(md.wrappedDataKeyB64));
        SecretKey dataKey = KEYS.unwrap(w);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = Base64.getDecoder().decode(md.ivB64);
        c.init(Cipher.DECRYPT_MODE, dataKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
        c.updateAAD(aad);
        byte[] plain = c.doFinal(cipher);

        Audit.log("DECRYPT " + md.imageId + " by " + userId);
        zeroize(dataKey.getEncoded());
        return plain;
    }

    public static void secureDelete(Path file, String userId, Set<String> roles) throws Exception {
        byte[] enc = Files.readAllBytes(file);
        int len = ByteBuffer.wrap(enc).getInt();
        byte[] aad = Arrays.copyOfRange(enc, 4, 4 + len);
        ImageMetadata md = ImageMetadata.fromBytes(aad);

        if (!ABAC.allowed("DELETE", md, userId, roles))
            throw new SecurityException("Not allowed");

        // overwrite 3×
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw")) {
            byte[] random = new byte[(int) raf.length()];
            for (int i = 0; i < 3; i++) {
                RNG.nextBytes(random);
                raf.seek(0);
                raf.write(random);
                raf.getFD().sync();
            }
        }
        Files.delete(file);
        Audit.log("DELETE " + md.imageId + " by " + userId);
    }

    /* --- util zeroization --- */
    private static void zeroize(byte[] data) {
        if (data != null) Arrays.fill(data, (byte) 0);
    }

    /* --- Demo simples --- */
    public static void main(String[] args) throws Exception {
        byte[] img = Files.readAllBytes(Path.of("foto.jpg"));
        String userId = "user123";
        Set<String> roles = Set.of("writer", "reader");

        byte[] enc = encryptImage(img, userId, roles, "biometria",
                LocalDateTime.now().plusYears(1));
        Files.write(Path.of("foto.enc"), enc);

        byte[] dec = decryptImage(enc, userId, roles);
        Files.write(Path.of("foto_decrypt.jpg"), dec);

        // secureDelete(Path.of("foto.enc"), userId, roles);
    }
}
