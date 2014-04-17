package org.jose4j.jwe;

import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;

/**
 *
 */
public class SimpleAeadCipher
{
    private String algorithm;
    private int tagByteLength;

    public SimpleAeadCipher(String algorithm, int tagByteLength)
    {
        this.algorithm = algorithm;
        this.tagByteLength = tagByteLength;
    }

    public Cipher getInitialisedCipher(Key key, byte[] iv, int mode) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(algorithm);
        try
        {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(ByteUtil.bitLength(tagByteLength), iv);
            cipher.init(mode, key, parameterSpec);
            return cipher;
        }
        catch (java.security.InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + algorithm, e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    public CipherOutput encrypt(Key key, byte[] iv, byte[] plaintext, byte[] aad) throws JoseException
    {
        Cipher cipher = getInitialisedCipher(key, iv, Cipher.ENCRYPT_MODE);
        updateAad(cipher, aad);

        byte[] cipherOutput;
        try
        {
            cipherOutput = cipher.doFinal(plaintext);
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

        CipherOutput result = new CipherOutput();
        int tagIndex = cipherOutput.length - tagByteLength;
        result.ciphertext = ByteUtil.subArray(cipherOutput, 0, tagIndex);
        result.tag = ByteUtil.subArray(cipherOutput, tagIndex, tagByteLength);
        return result;
    }

    private void updateAad(Cipher cipher, byte[] aad)
    {
        if (aad != null && aad.length > 0)
        {
            cipher.updateAAD(aad);
        }
    }

    public byte[] decrypt(Key key, byte[] iv, byte[] ciphertext, byte[] tag, byte[] aad) throws JoseException
    {
        Cipher cipher = getInitialisedCipher(key, iv, Cipher.DECRYPT_MODE);
        updateAad(cipher, aad);

        try
        {
            return cipher.doFinal(ByteUtil.concat(ciphertext,tag));
        }
        catch (IllegalBlockSizeException | BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

    }

    public static class CipherOutput
    {
        private byte[] ciphertext;
        private byte[] tag;

        public byte[] getCiphertext()
        {
            return ciphertext;
        }

        public byte[] getTag()
        {
            return tag;
        }
    }
}
