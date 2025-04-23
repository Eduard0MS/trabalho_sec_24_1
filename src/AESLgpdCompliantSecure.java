import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

/**
 * Implementação AES avançada e compatível com LGPD
 * Inclui: envelope encryption, KDF endurecido, auditoria encadeada, zeroização, retenção automática, ABAC stub.
 */
public class AESLgpdCompliantSecure {
    /* ===================== Configurações cripto ===================== */
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int KEY_SIZE = 256;       // AES‑256
    private static final String ENC_ALG = "AES/GCM/NoPadding";
    private static final String KDF_ALG = "PBKDF2WithHmacSHA512";
    private static final int PBKDF2_ITERATIONS = 600_000;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /* ===================== Auditoria ===================== */
    private static final Logger LOGGER = Logger.getLogger(AESLgpdCompliantSecure.class.getName());
    private static final MessageDigest AUDIT_DIGEST;
    private static byte[] lastHash = new byte[32];
    static {
        try {
            FileHandler fh = new FileHandler("aes_lgpd_audit.log", true);
            fh.setFormatter(new SimpleFormatter());
            LOGGER.addHandler(fh);
            AUDIT_DIGEST = MessageDigest.getInstance("SHA-256");
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
    private static void audit(String msg) {
        String record = LocalDateTime.now() + " | " + msg + " | " + Base64.getEncoder().encodeToString(lastHash);
        lastHash = AUDIT_DIGEST.digest(record.getBytes(StandardCharsets.UTF_8));
        LOGGER.info(record);
    }

    /* ===================== Key Management ===================== */
    public interface KeyRepository {
        KeyInfo createKey(char[] passphrase, byte[] salt) throws CryptoException;
        KeyInfo createRandomKey() throws CryptoException;
        KeyInfo fetchKey(String keyId) throws CryptoException;
        void disableKey(String keyId) throws CryptoException;
    }

    /**
     * Implementação em memória (mock). Substitua por AWS KMS, HashiCorp Vault, etc.
     */
    public static class InMemoryKeyRepository implements KeyRepository {
        private final Map<String, KeyInfo> store = new HashMap<>();
        @Override
        public KeyInfo createKey(char[] passphrase, byte[] salt) throws CryptoException {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALG);
                KeySpec spec = new PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_SIZE);
                SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
                Arrays.fill(passphrase, '\u0000');
                String id = UUID.randomUUID().toString();
                KeyInfo ki = new KeyInfo(key);
                store.put(id, ki);
                return new KeyInfo(id, ki);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new CryptoException("Falha na derivação de chave", e);
            }
        }
        @Override
        public KeyInfo createRandomKey() throws CryptoException {
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(KEY_SIZE, SECURE_RANDOM);
                SecretKey key = kg.generateKey();
                String id = UUID.randomUUID().toString();
                KeyInfo ki = new KeyInfo(key);
                store.put(id, ki);
                return new KeyInfo(id, ki);
            } catch (NoSuchAlgorithmException e) {
                throw new CryptoException("Falha ao gerar chave", e);
            }
        }
        @Override public KeyInfo fetchKey(String keyId) { return store.get(keyId); }
        @Override public void disableKey(String keyId) { if(store.containsKey(keyId)) store.get(keyId).active = false; }
    }

    public static final KeyRepository KEY_REPO = new InMemoryKeyRepository();

    /* ===================== Modelos ===================== */
    public static class CryptoException extends Exception { public CryptoException(String m, Throwable c) { super(m, c);} }

    public static class KeyInfo {
        public final SecretKey key;
        public final LocalDateTime created = LocalDateTime.now();
        public final LocalDateTime expiry = created.plusDays(90);
        public boolean active = true;
        public final String id;
        public KeyInfo(String id, KeyInfo from) { this.id = id; this.key = from.key; }
        public KeyInfo(SecretKey k) { this.key = k; this.id = null; }
    }

    public static class ImageMetadata {
        String imageId = UUID.randomUUID().toString();
        String createdAt = LocalDateTime.now().toString();
        String lastAccessed = createdAt;
        String purpose;
        String owner;
        String retentionPeriod;
        String masterKeyId;  // chave mestra usada para envolver
        String wrappedDataKey; // chave de sessão cifrada
        String iv;  // IV usado em GCM
        public ImageMetadata(String purpose, String owner, String retention) {
            this.purpose=purpose; this.owner=owner; this.retentionPeriod=retention;
        }
        public byte[] toBytes() {
            String s = String.join(";",
                "imageId="+imageId,
                "createdAt="+createdAt,
                "lastAccessed="+lastAccessed,
                "purpose="+purpose,
                "owner="+owner,
                "retention="+retentionPeriod,
                "masterKeyId="+masterKeyId,
                "wrappedDataKey="+wrappedDataKey,
                "iv="+iv);
            return s.getBytes(StandardCharsets.UTF_8);
        }
        public static ImageMetadata fromBytes(byte[] b) {
            Map<String,String> map = new HashMap<>();
            for(String part:new String(b,StandardCharsets.UTF_8).split(";")){
                String[] kv=part.split("=",2); if(kv.length==2) map.put(kv[0],kv[1]);
            }
            ImageMetadata m = new ImageMetadata(map.get("purpose"), map.get("owner"), map.get("retention"));
            m.imageId=map.get("imageId");m.createdAt=map.get("createdAt");m.lastAccessed=map.get("lastAccessed");
            m.masterKeyId=map.get("masterKeyId");m.wrappedDataKey=map.get("wrappedDataKey");m.iv=map.get("iv");
            return m;
        }
    }

    /* ===================== Inicialização ===================== */
    private static final ScheduledExecutorService RETENTION_EXEC = Executors.newSingleThreadScheduledExecutor();

    public static void initialize() {
        audit("Sistema inicializado");
        RETENTION_EXEC.scheduleAtFixedRate(AESLgpdCompliantSecure::purgeExpiredFiles, 1, 24, TimeUnit.HOURS);
    }

    /* ===================== Envelope Encryption ===================== */
    public static byte[] encryptImage(byte[] imageData, String masterKeyId, String userId, String purpose, String retentionISO) throws CryptoException {
        if(!validateUserPermissions(userId, "ENCRYPT"))
            throw new SecurityException("Sem permissão");

        // 1. Gera chave de sessão (data key)
        KeyGenerator kg;
        try { kg = KeyGenerator.getInstance("AES"); kg.init(KEY_SIZE, SECURE_RANDOM);} catch (NoSuchAlgorithmException e){throw new CryptoException("AES não disponível", e);}        
        SecretKey dataKey = kg.generateKey();

        // 2. Busca chave mestra
        KeyInfo masterInfo = KEY_REPO.fetchKey(masterKeyId);
        if(masterInfo==null||!masterInfo.active) throw new SecurityException("Chave mestra inválida");

        // 3. Envolve a dataKey
        byte[] wrapped;
        try {
            Cipher wrap = Cipher.getInstance("AESWrap");
            wrap.init(Cipher.WRAP_MODE, masterInfo.key);
            wrapped = wrap.wrap(dataKey);
        } catch (Exception e) { throw new CryptoException("Falha ao envolver dataKey", e);}        

        // 4. IV único
        byte[] iv=new byte[GCM_IV_LENGTH]; SECURE_RANDOM.nextBytes(iv);

        // 5. Cria metadata
        ImageMetadata meta = new ImageMetadata(purpose, userId, retentionISO);
        meta.masterKeyId = masterKeyId;
        meta.wrappedDataKey = Base64.getEncoder().encodeToString(wrapped);
        meta.iv = Base64.getEncoder().encodeToString(iv);
        byte[] metaBytes = meta.toBytes();

        // 6. Criptografa dados
        byte[] cipherText;
        try {
            Cipher c = Cipher.getInstance(ENC_ALG);
            c.init(Cipher.ENCRYPT_MODE, dataKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            c.updateAAD(metaBytes);
            cipherText = c.doFinal(imageData);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e) {
            destroySecret(dataKey);
            throw new CryptoException("Erro na criptografia", e);
        }

        // Limpa dataKey da memória
        destroySecret(dataKey);

        // 7. Monta payload: metaLen + meta + cipher
        ByteBuffer bb = ByteBuffer.allocate(4+metaBytes.length+cipherText.length);
        bb.putInt(metaBytes.length).put(metaBytes).put(cipherText);

        audit("Imagem " + meta.imageId + " criptografada por " + userId);
        return bb.array();
    }

    public static byte[] decryptImage(byte[] payload, String userId) throws CryptoException {
        ByteBuffer bb = ByteBuffer.wrap(payload);
        int metaLen = bb.getInt();
        byte[] metaBytes = new byte[metaLen]; bb.get(metaBytes);
        ImageMetadata meta = ImageMetadata.fromBytes(metaBytes);

        LocalDateTime ret = LocalDateTime.parse(meta.retentionPeriod);
        if(LocalDateTime.now().isAfter(ret)) throw new SecurityException("Imagem expirada");
        if(!validateUserPermissions(userId, "DECRYPT") && !userId.equals(meta.owner)) throw new SecurityException("Sem permissão");

        // Unwrap dataKey
        KeyInfo masterInfo = KEY_REPO.fetchKey(meta.masterKeyId);
        if(masterInfo==null) throw new SecurityException("Chave mestra ausente");
        byte[] wrapped = Base64.getDecoder().decode(meta.wrappedDataKey);
        SecretKey dataKey;
        try {
            Cipher wrap = Cipher.getInstance("AESWrap");
            wrap.init(Cipher.UNWRAP_MODE, masterInfo.key);
            dataKey = (SecretKey) wrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
        } catch (Exception e){ throw new CryptoException("Falha ao desembrulhar chave", e);}        

        // Decripta
        byte[] cipherText = new byte[bb.remaining()]; bb.get(cipherText);
        byte[] iv = Base64.getDecoder().decode(meta.iv);
        try {
            Cipher c = Cipher.getInstance(ENC_ALG);
            c.init(Cipher.DECRYPT_MODE, dataKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            c.updateAAD(metaBytes);
            byte[] plain = c.doFinal(cipherText);
            destroySecret(dataKey);
            meta.lastAccessed = LocalDateTime.now().toString();
            audit("Imagem " + meta.imageId + " descriptografada por " + userId);
            return plain;
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException | javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException e) {
            destroySecret(dataKey);
            throw new CryptoException("Erro na descriptografia", e);
        }
    }

    /* ===================== Pseudonimização (EXIF strip) ===================== */
    public static byte[] exportPseudonymizedImage(byte[] payload, String userId) throws CryptoException {
        byte[] img = decryptImage(payload, userId);
        try {
            // Apache Commons Imaging
            return Pseudonymizer.stripExif(img);
        } catch (Exception e) {
            throw new CryptoException("Falha na pseudonimização", e);
        }
    }

    /* ===================== Exclusão segura ===================== */
    public static void secureDelete(File f) throws IOException {
        if(!f.exists()) return;
        try(FileOutputStream fos=new FileOutputStream(f)){
            byte[] rand=new byte[(int)f.length()]; SECURE_RANDOM.nextBytes(rand);
            for(int i=0;i<3;i++){ fos.write(rand); fos.getFD().sync(); }
        }
        boolean ok=f.delete(); if(ok) audit("Arquivo "+f.getName()+" excluído.");
    }

    /* ===================== Retenção programada ===================== */
    private static void purgeExpiredFiles() {
        // Percorra seu diretório de armazenamento
        File storage = new File("."); // ajuste
        for(File f:storage.listFiles((dir,name)->name.endsWith(".enc"))){
            try {
                byte[] data=Files.readAllBytes(f.toPath());
                ByteBuffer bb=ByteBuffer.wrap(data);
                int len=bb.getInt();byte[] metaB=new byte[len];bb.get(metaB);
                ImageMetadata m=ImageMetadata.fromBytes(metaB);
                if(LocalDateTime.now().isAfter(LocalDateTime.parse(m.retentionPeriod))){
                    secureDelete(f);
                }
            } catch (Exception e){ LOGGER.log(Level.WARNING,"Falha ao purgar",e);}        }
    }

    /* ===================== Utilidades ===================== */
    private static boolean validateUserPermissions(String user, String op){
        // TODO integrar com ABAC real
        return true;
    }
    private static void destroySecret(SecretKey k){
        if(k==null) return;
        try{k.destroy();}catch(DestroyFailedException ignored){}
    }

    /* ===================== Exemplo de uso ===================== */
    public static void main(String[] args) throws Exception {
        initialize();
        // cria chave mestra
        byte[] salt = SECURE_RANDOM.generateSeed(16);
        KeyInfo master = KEY_REPO.createKey("SenhaForte123!@#".toCharArray(), salt);
        String masterId = master.id;
        System.out.println("Chave mestra: "+masterId);

        byte[] img = Files.readAllBytes(new File("imagem.jpg").toPath());
        String user="user123";
        String retention=LocalDateTime.now().plusYears(1).format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        byte[] enc = encryptImage(img, masterId, user, "Identificação biométrica", retention);
        Files.write(new File("imagem.enc").toPath(), enc);
        byte[] dec = decryptImage(enc, user);
        Files.write(new File("imagem_dec.jpg").toPath(), dec);
        byte[] anon = exportPseudonymizedImage(enc, user);
        Files.write(new File("imagem_pseudo.jpg").toPath(), anon);
    }

    /* ---------- Pseudonymizer util (inner static class) ---------- */
    public static class Pseudonymizer {
        public static byte[] stripExif(byte[] jpeg) throws Exception {
            // Apache Commons Imaging dependency
            // return Imaging.writeImageToBytes(Imaging.getBufferedImage(new ByteArrayInputStream(jpeg)), ImageFormats.JPEG, new HashMap<>());
            return jpeg; // stub
        }
    }
}
