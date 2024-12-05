package com.artyomf.encryption.cipher;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Class that provides {@link Cipher} both for encryption and decryption operations
 */
@Slf4j
public class CipherProvider {
    private final String algorithm;

    /**
     * Initializes CipherProvider
     * Loads algorithm to validate string argument eagerly
     */
    public CipherProvider(String algorithm) {
        this.algorithm = algorithm;
        loadAlgorithm();
    }

    /**
     * Initializes and returns a cipher for encryption. Parameters (e.g. IV) are generated internally
     * @param key encryption key
     * @return prepared {@link Cipher} instance
     * @throws EncryptionException if key or IV don't match algorithm
     */
    public Cipher provideCipherForEncryption(byte[] key) {
        Cipher cipher = loadAlgorithm();
        SecretKeySpec keySpec = new SecretKeySpec(key, cipher.getParameters().getAlgorithm());
        return initializeCipher(cipher, Cipher.ENCRYPT_MODE, keySpec, null);
    }

    /**
     * Initializes and returns a cipher for decryption
     * @param key decryption key
     * @param initializationVector IV used for encryption
     * @return prepared {@link Cipher} instance
     * @throws EncryptionException if key or IV don't match algorithm
     */
    public Cipher provideCipherForDecryption(byte[] key, byte[] initializationVector) {
        Cipher cipher = loadAlgorithm();
        SecretKeySpec keySpec = new SecretKeySpec(key, cipher.getParameters().getAlgorithm());
        IvParameterSpec parameterSpec = new IvParameterSpec(initializationVector);
        return initializeCipher(cipher, Cipher.DECRYPT_MODE, keySpec, parameterSpec);
    }

    private Cipher initializeCipher(Cipher cipher, int mode, Key keySpec, AlgorithmParameterSpec parameterSpec) {
        try {
            if (parameterSpec == null) {
                cipher.init(mode, keySpec);
            } else {
                cipher.init(mode, keySpec, parameterSpec);
            }
            return cipher;
        } catch (InvalidKeyException e) {
            log.error("Invalid key format for algorithm {}", algorithm, e);
            throw new EncryptionException(EncryptionException.Type.INVALID_KEY, e);
        } catch (InvalidAlgorithmParameterException e) {
            log.error("Invalid parameters for algorithm {}", algorithm, e);
            throw new EncryptionException(EncryptionException.Type.INVALID_PARAMS, e);
        }
    }

    private Cipher loadAlgorithm() {
        try {
            return Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new CipherInitializationException("Failed to load algorithm " + algorithm, e);
        }
    }
}
