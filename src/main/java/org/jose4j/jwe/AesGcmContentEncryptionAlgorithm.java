package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

/**
 *
 */
public class AesGcmContentEncryptionAlgorithm extends AlgorithmInfo implements ContentEncryptionAlgorithm
{
    private static final int IV_BYTE_LENGTH = 12;
    private static final int TAG_BYTE_LENGTH = 16;

    private ContentEncryptionKeyDescriptor contentEncryptionKeyDescriptor;
    private SimpleAeadCipher simpleAeadCipher;

    public AesGcmContentEncryptionAlgorithm(String alg, int keyBitLength)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm(SimpleAeadCipher.GCM_TRANSFORMATION_NAME);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
        contentEncryptionKeyDescriptor = new ContentEncryptionKeyDescriptor(ByteUtil.byteLength(keyBitLength), AesKey.ALGORITHM);
        simpleAeadCipher = new SimpleAeadCipher(getJavaAlgorithm(), TAG_BYTE_LENGTH);
    }

    public ContentEncryptionKeyDescriptor getContentEncryptionKeyDescriptor()
    {
        return contentEncryptionKeyDescriptor;
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, Headers headers, byte[] ivOverride)
            throws JoseException
    {
        byte[] iv = InitializationVectorHelp.iv(IV_BYTE_LENGTH, ivOverride);
        return encrypt(plaintext, aad, contentEncryptionKey, iv);
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, byte[] iv)
            throws JoseException
    {
        AesKey cek = new AesKey(contentEncryptionKey);
        SimpleAeadCipher.CipherOutput encrypted = simpleAeadCipher.encrypt(cek, iv, plaintext, aad);
        return new ContentEncryptionParts(iv, encrypted.getCiphertext(), encrypted.getTag());
    }

    public byte[] decrypt(ContentEncryptionParts contentEncParts, byte[] aad, byte[] contentEncryptionKey, Headers headers)
            throws JoseException
    {
        byte[] iv = contentEncParts.getIv();
        AesKey cek = new AesKey(contentEncryptionKey);
        byte[] ciphertext = contentEncParts.getCiphertext();
        byte[] tag = contentEncParts.getAuthenticationTag();
        return simpleAeadCipher.decrypt(cek, iv, ciphertext, tag, aad);
    }

    @Override
    public boolean isAvailable()
    {
        int keyByteLength = getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
        return simpleAeadCipher.isAvailable(log, keyByteLength, IV_BYTE_LENGTH, getAlgorithmIdentifier());
    }

    /**
     */
    public static class Aes256Gcm extends AesGcmContentEncryptionAlgorithm
    {
        public Aes256Gcm()
        {
            super(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM, 256);
        }
    }

    /**
     *
     */
    public static class Aes192Gcm extends AesGcmContentEncryptionAlgorithm
    {
        public Aes192Gcm()
        {
            super(ContentEncryptionAlgorithmIdentifiers.AES_192_GCM, 192);
        }
    }

    /**
     *
     */
    public static class Aes128Gcm extends AesGcmContentEncryptionAlgorithm
    {
        public Aes128Gcm()
        {
            super(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, 128);
        }
    }
}