import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;

public class AES {

    private static final int Nb = 4;  // Número de colunas (32 bits cada)
    private static int Nk;  // Número de palavras na chave (32 bits cada)
    private final int Nr;  // Número de rodadas, definido dinamicamente

    private final byte[][] roundKeys;

    // S-Box e Inverse S-Box omitidos para brevidade
    // S-box completa omitida por brevidade
    private static final byte[] sbox = {
            (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5,
            (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B, (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76,
            (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0,
            (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF, (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0,
            (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7, (byte) 0xCC,
            (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1, (byte) 0x71, (byte) 0xD8, (byte) 0x31, (byte) 0x15,
            (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9A,
            (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2, (byte) 0xEB, (byte) 0x27, (byte) 0xB2, (byte) 0x75,
            (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A, (byte) 0xA0,
            (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3, (byte) 0x29, (byte) 0xE3, (byte) 0x2F, (byte) 0x84,
            (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1, (byte) 0x5B,
            (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39, (byte) 0x4A, (byte) 0x4C, (byte) 0x58, (byte) 0xCF,
            (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33, (byte) 0x85,
            (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F, (byte) 0x50, (byte) 0x3C, (byte) 0x9F, (byte) 0xA8,
            (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5,
            (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21, (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2,
            (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17,
            (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D, (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73,
            (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88,
            (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14, (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB,
            (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C,
            (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79,
            (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9,
            (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA, (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08,
            (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6,
            (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F, (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A,
            (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E,
            (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9, (byte) 0x86, (byte) 0xC1, (byte) 0x1D, (byte) 0x9E,
            (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94,
            (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9, (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF,
            (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68,
            (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F, (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16
    };



    // Inverse S-box completa omitida por brevidade
    private static final byte[] invSbox = {
            (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38,
            (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB,
            (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87,
            (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB,
            (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D,
            (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E,
            (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2,
            (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25,
            (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16,
            (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92,
            (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA,
            (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84,
            (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A,
            (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06,
            (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02,
            (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B,
            (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA,
            (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73,
            (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85,
            (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E,
            (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89,
            (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B,
            (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20,
            (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4,
            (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31,
            (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F,
            (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D,
            (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF,
            (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0,
            (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61,
            (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26,
            (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D
    };




    private static final byte[] rcon = {
            (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x08, (byte) 0x10, (byte) 0x20, (byte) 0x40,
            (byte) 0x80, (byte) 0x1B, (byte) 0x36
    };

    public AES(byte[] key, int numRounds) {
        Nk = key.length / 4;  // Calcula Nk baseado no tamanho da chave
        if (numRounds == 1 || numRounds == 5 || numRounds == 9 || numRounds == 13) {
            this.Nr = numRounds;
        } else {
            throw new IllegalArgumentException("Número de rodadas inválido. Use 1, 5, 9 ou 13 rodadas.");
        }
        this.roundKeys = new byte[Nb * (Nr + 1)][4];
        keyExpansion(key);
    }

    // Inverso do Shift Rows (deslocar linhas)
    private static byte[] invShiftRows(byte[] state) {
        byte[] newState = new byte[state.length];
        System.arraycopy(state, 0, newState, 0, state.length);
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                newState[i * Nb + j] = state[i * Nb + (j - i + Nb) % Nb];
            }
        }
        return newState;
    }

    // Substituir bytes usando a Inverse S-box
    private static byte[] invSubBytes(byte[] state) {
        byte[] newState = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            newState[i] = invSbox[state[i] & 0xFF];
        }
        return newState;
    }


    // Expansão da chave
    private void keyExpansion(byte[] key) {
        byte[] temp = new byte[4];
        for (int i = 0; i < Nk; i++) {
            roundKeys[i] = Arrays.copyOfRange(key, i * 4, (i + 1) * 4);
        }
        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            temp = roundKeys[i - 1];
            if (i % Nk == 0) {
                temp = subBytes(rotateWord(temp));
                temp[0] ^= rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subBytes(temp);
            }
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = (byte) (roundKeys[i - Nk][j] ^ temp[j]);
            }
        }
    }

    // Rodar uma palavra (usado na expansão da chave)
    private static byte[] rotateWord(byte[] word) {
        byte[] newWord = new byte[word.length];
        System.arraycopy(word, 1, newWord, 0, word.length - 1);
        newWord[word.length - 1] = word[0];
        return newWord;
    }

    // Substituir bytes usando a S-box
    private static byte[] subBytes(byte[] state) {
        byte[] newState = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            newState[i] = sbox[state[i] & 0xFF];
        }
        return newState;
    }

    // Shift Rows (deslocar linhas)
    private static byte[] shiftRows(byte[] state) {
        byte[] newState = new byte[state.length];
        System.arraycopy(state, 0, newState, 0, state.length);
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < Nb; j++) {
                newState[i * Nb + j] = state[i * Nb + (j + i) % Nb];
            }
        }
        return newState;
    }

    // Mix Columns (misturar colunas)
    private static byte[] mixColumns(byte[] state) {
        byte[] newState = new byte[state.length];
        for (int i = 0; i < Nb; i++) {
            newState[i * 4] = (byte) (mulBy2(state[i * 4]) ^ mulBy3(state[i * 4 + 1]) ^ state[i * 4 + 2] ^ state[i * 4 + 3]);
            newState[i * 4 + 1] = (byte) (state[i * 4] ^ mulBy2(state[i * 4 + 1]) ^ mulBy3(state[i * 4 + 2]) ^ state[i * 4 + 3]);
            newState[i * 4 + 2] = (byte) (state[i * 4] ^ state[i * 4 + 1] ^ mulBy2(state[i * 4 + 2]) ^ mulBy3(state[i * 4 + 3]));
            newState[i * 4 + 3] = (byte) (mulBy3(state[i * 4]) ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ mulBy2(state[i * 4 + 3]));
        }
        return newState;
    }

    // Inverso do Mix Columns
    private static byte[] invMixColumns(byte[] state) {
        byte[] newState = new byte[state.length];
        for (int i = 0; i < Nb; i++) {
            newState[i * 4] = (byte) (mulByE(state[i * 4]) ^ mulByB(state[i * 4 + 1]) ^ mulByD(state[i * 4 + 2]) ^ mulBy9(state[i * 4 + 3]));
            newState[i * 4 + 1] = (byte) (mulBy9(state[i * 4]) ^ mulByE(state[i * 4 + 1]) ^ mulByB(state[i * 4 + 2]) ^ mulByD(state[i * 4 + 3]));
            newState[i * 4 + 2] = (byte) (mulByD(state[i * 4]) ^ mulBy9(state[i * 4 + 1]) ^ mulByE(state[i * 4 + 2]) ^ mulByB(state[i * 4 + 3]));
            newState[i * 4 + 3] = (byte) (mulByB(state[i * 4]) ^ mulByD(state[i * 4 + 1]) ^ mulBy9(state[i * 4 + 2]) ^ mulByE(state[i * 4 + 3]));
        }
        return newState;
    }

    // Funções de multiplicação no campo de Galois
    private static byte mulBy2(byte i) {
        return (byte) (((i << 1) ^ (((i >> 7) & 1) * 0x1B)) & 0xFF);
    }

    private static byte mulBy3(byte i) {
        return (byte) (mulBy2(i) ^ i);
    }

    private static byte mulBy9(byte i) {
        return (byte) (mulBy2(mulBy2(mulBy2(i))) ^ i);
    }

    private static byte mulByB(byte i) {
        return (byte) (mulBy2(mulBy2(mulBy2(i))) ^ mulBy2(i) ^ i);
    }

    private static byte mulByD(byte i) {
        return (byte) (mulBy2(mulBy2(mulBy2(i))) ^ mulBy2(mulBy2(i)) ^ i);
    }

    private static byte mulByE(byte i) {
        return (byte) (mulBy2(mulBy2(mulBy2(i))) ^ mulBy2(mulBy2(i)) ^ mulBy2(i));
    }

    // Adicionar a chave da rodada ao estado
    private static byte[] addRoundKey(byte[] state, byte[] roundKey) {
        byte[] newState = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            newState[i] = (byte) (state[i] ^ roundKey[i % roundKey.length]);
        }
        return newState;
    }


    // Cifração AES
    public byte[] encrypt(byte[] input) {
        byte[] state = Arrays.copyOf(input, input.length);
        state = addRoundKey(state, roundKeys[0]);
        for (int round = 1; round < Nr; round++) {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, roundKeys[round]);
        }
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, roundKeys[Nr]);
        return state;
    }

    // Decifração AES
    public byte[] decrypt(byte[] input) {
        byte[] state = Arrays.copyOf(input, input.length);
        state = addRoundKey(state, roundKeys[Nr]);
        for (int round = Nr - 1; round > 0; round--) {
            state = invShiftRows(state);
            state = invSubBytes(state);
            state = addRoundKey(state, roundKeys[round]);
            state = invMixColumns(state);
        }
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, roundKeys[0]);
        return state;
    }



    // Implementação do modo de operação CTR
    public byte[] ctrEncrypt(byte[] input, byte[] nonce) {
        int numBlocks = (int) Math.ceil((double) input.length / (4 * Nb));
        byte[] output = new byte[input.length];
        byte[] counter = Arrays.copyOf(nonce, nonce.length);

        for (int i = 0; i < numBlocks; i++) {
            byte[] encryptedCounter = encrypt(counter);
            for (int j = 0; j < 4 * Nb && i * 4 * Nb + j < input.length; j++) {
                output[i * 4 * Nb + j] = (byte) (input[i * 4 * Nb + j] ^ encryptedCounter[j]);
            }
            incrementCounter(counter);
        }

        return output;
    }

    // Incrementar o contador
    private void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }

    // Implementação do modo GCM (simplificado)
    public byte[] gcmEncrypt(byte[] input, byte[] nonce) {
        byte[] ciphertext = ctrEncrypt(input, nonce);
        byte[] tag = generateTag(ciphertext, nonce);
        byte[] output = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, output, 0, ciphertext.length);
        System.arraycopy(tag, 0, output, ciphertext.length, tag.length);
        return output;
    }

    // Geração de tag para GCM
    private byte[] generateTag(byte[] ciphertext, byte[] nonce) {
        byte[] tag = new byte[16];
        byte[] h = encrypt(new byte[16]);

        for (int i = 0; i < ciphertext.length; i += 16) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, Math.min(i + 16, ciphertext.length));
            galoisMultiply(tag, block);
        }
        galoisMultiply(tag, nonce);
        return tag;
    }

    // Multiplicação no campo de Galois
    private void galoisMultiply(byte[] x, byte[] y) {
        byte[] z = new byte[16];
        for (int i = 0; i < 128; i++) {
            if ((y[i / 8] & (1 << (7 - (i % 8)))) != 0) {
                for (int j = 0; j < 16; j++) {
                    z[j] ^= x[j];
                }
            }
            boolean lsbSet = (x[15] & 1) != 0;
            for (int j = 15; j > 0; j--) {
                x[j] = (byte) ((x[j] >> 1) | ((x[j - 1] & 1) << 7));
            }
            x[0] >>= 1;
            if (lsbSet) x[0] ^= (byte) 0xe1;
        }
        System.arraycopy(z, 0, x, 0, 16);
    }

    public static void main(String[] args) throws Exception {
        // Caminho para o arquivo de imagem
        File imageFile = new File("C:\\Users\\61488665362\\IdeaProjects\\seguranca\\src\\selfie.jpg");
        byte[] imageData = Files.readAllBytes(imageFile.toPath());

        // Chave de 192 bits e nonce (IV)
        byte[] key = {
                (byte) 0x2B, (byte) 0x7E, (byte) 0x15, (byte) 0x16, (byte) 0x28, (byte) 0xAE, (byte) 0xD2,
                (byte) 0xA6, (byte) 0xAB, (byte) 0xF7, (byte) 0x4F, (byte) 0xAD, (byte) 0x12, (byte) 0x4D,
                (byte) 0xB2, (byte) 0x03, (byte) 0xB6, (byte) 0xF7, (byte) 0x4F, (byte) 0xAD, (byte) 0x12,
                (byte) 0x4D, (byte) 0xB2, (byte) 0x03
        };

        byte[] nonce = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F
        };;

        int[] rodadas = {1, 5, 9, 13};

        for (int rodada : rodadas) {
            // Criptografia da imagem
            AES aes = new AES(key, rodada);  // Passando o número de rodadas
            byte[] encryptedData = aes.ctrEncrypt(imageData, nonce);
            File encryptedFile = new File("src/selfie_encrypted_" + rodada + "_rounds.jpg");
            Files.write(encryptedFile.toPath(), encryptedData);
            System.out.println("Imagem cifrada com " + rodada + " rodadas e salva como " + encryptedFile.getName());

            // Descriptografia da imagem criptografada
            byte[] decryptedData = aes.ctrEncrypt(encryptedData, nonce); // Como estamos usando CTR, criptografia e descriptografia são simétricas
            File decryptedFile = new File("src/selfie_decrypted_" + rodada + "_rounds.jpg");
            Files.write(decryptedFile.toPath(), decryptedData);
            System.out.println("Imagem descriptografada com " + rodada + " rodadas e salva como " + decryptedFile.getName());
        }
    }
}
