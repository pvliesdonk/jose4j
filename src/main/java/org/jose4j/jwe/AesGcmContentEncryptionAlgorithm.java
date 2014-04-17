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
        setJavaAlgorithm("AES/GCM/NoPadding");
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
        boolean isAvailable = false;
        // The Sun/Oracle provider in Java 7 doesn't have GCM.
        // Bouncy Castle prior to 1.50 would let you get a cipher with AES/GCM/NoPadding but it but
        // didn't fully support the JCE AEAD interfaces and would fail (on initialization with the
        // GCMParameterSpec IIRC) when trying to encrypt/decrypt. So seems the only good way to see if GCM
        // is really there is to try it...
        int aesByteKeyLength = getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
        String agl = getJavaAlgorithm();
        if (CipherStrengthSupport.isAvailable(agl, aesByteKeyLength))
        {
            byte[] plain = new byte[] {112,108,97,105,110,116,101,120,116};
            byte[] aad = new byte[] {97,97,100};
            byte[] cek = ByteUtil.randomBytes(aesByteKeyLength);
            try
            {
                encrypt(plain, aad, cek, null, null);
                isAvailable = true;
            }
            catch (JoseException e)
            {
                log.debug(getAlgorithmIdentifier() + " is not available (" + e + ").");
            }
        }
        return isAvailable;
    }
}