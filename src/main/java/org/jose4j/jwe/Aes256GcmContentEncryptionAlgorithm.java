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
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 */
public class Aes256GcmContentEncryptionAlgorithm extends AlgorithmInfo implements ContentEncryptionAlgorithm
{
    public static final int IV_BYTE_LENGTH = 12;
    public static final int TAG_BYTE_LENGTH = 16;

    private ContentEncryptionKeyDescriptor contentEncryptionKeyDescriptor = new ContentEncryptionKeyDescriptor(256, AesKey.ALGORITHM);

    public Aes256GcmContentEncryptionAlgorithm()
    {
        setAlgorithmIdentifier(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);
        setJavaAlgorithm("AES/GCM/NoPadding");
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        setKeyType(AesKey.ALGORITHM);
    }

    public ContentEncryptionKeyDescriptor getContentEncryptionKeyDescriptor()
    {
        return contentEncryptionKeyDescriptor;
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, Headers headers) throws JoseException
    {
        byte[] iv = ByteUtil.randomBytes(IV_BYTE_LENGTH);
        return encrypt(plaintext, aad, contentEncryptionKey, iv);
    }

    public ContentEncryptionParts encrypt(byte[] plaintext, byte[] aad, byte[] contentEncryptionKey, byte[] iv) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());

        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, new AesKey(contentEncryptionKey), new IvParameterSpec(iv));
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }

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

    public byte[] decrypt(ContentEncryptionParts contentEncryptionParts, byte[] aad, byte[] contentEncryptionKey, Headers headers) throws JoseException
    {
        return new byte[0];  // todo
    }
}
