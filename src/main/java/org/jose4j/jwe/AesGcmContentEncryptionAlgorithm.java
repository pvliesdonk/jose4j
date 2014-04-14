package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 *
 */
public class AesGcmContentEncryptionAlgorithm extends AlgorithmInfo implements ContentEncryptionAlgorithm
{
    public static final int IV_BYTE_LENGTH = 12;
    public static final int TAG_BYTE_LENGTH = 16;
    public static final int TAG_BIT_LENGTH = ByteUtil.bitLength(TAG_BYTE_LENGTH);

    private ContentEncryptionKeyDescriptor contentEncryptionKeyDescriptor;

    public AesGcmContentEncryptionAlgorithm(String alg, int keyBitLength)
    {
        setAlgorithmIdentifier(alg);
        setJavaAlgorithm("AES/GCM/NoPadding");
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
        contentEncryptionKeyDescriptor = new ContentEncryptionKeyDescriptor(ByteUtil.byteLength(keyBitLength), AesKey.ALGORITHM);
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
        Cipher cipher = getInitialisedCipher(Cipher.ENCRYPT_MODE, iv, contentEncryptionKey);

        cipher.updateAAD(aad);

        byte[] cipherOutput;
        try
        {
            cipherOutput = cipher.doFinal(plaintext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

        int tagIndex = cipherOutput.length - TAG_BYTE_LENGTH;
        byte[] ciphertext = ByteUtil.subArray(cipherOutput, 0, tagIndex);
        byte[] tag = ByteUtil.subArray(cipherOutput, tagIndex, TAG_BYTE_LENGTH);

        return new ContentEncryptionParts(iv, ciphertext, tag);
    }

    Cipher getInitialisedCipher(int mode, byte[] iv, byte[] rawKey) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());
        try
        {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_BIT_LENGTH, iv);
            cipher.init(mode, new AesKey(rawKey), parameterSpec);
            return cipher;
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    public byte[] decrypt(ContentEncryptionParts contentEncParts, byte[] aad, byte[] contentEncryptionKey, Headers headers)
            throws JoseException
    {
        byte[] iv = contentEncParts.getIv();
        Cipher cipher = getInitialisedCipher(Cipher.DECRYPT_MODE, iv, contentEncryptionKey);

        cipher.updateAAD(aad);

        byte[] ciphertext = ByteUtil.concat(contentEncParts.getCiphertext(), contentEncParts.getAuthenticationTag());

        try
        {
            return cipher.doFinal(ciphertext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }
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