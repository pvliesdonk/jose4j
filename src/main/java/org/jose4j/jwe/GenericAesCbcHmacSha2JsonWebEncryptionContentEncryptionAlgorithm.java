package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.mac.MacUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 */
public class GenericAesCbcHmacSha2JsonWebEncryptionContentEncryptionAlgorithm extends AlgorithmInfo implements JsonWebEncryptionContentEncryptionAlgorithm
{
    private String hmacJavaAlgorithm;
    private int tagTruncationLength;
    private int keySize;

    public GenericAesCbcHmacSha2JsonWebEncryptionContentEncryptionAlgorithm()
    {
        setJavaAlgorithm("AES/CBC/PKCS5Padding");
    }

    public int getKeySize()
    {
        return keySize;
    }

    public void setKeySize(int keySize)
    {
        this.keySize = keySize;
    }

    public String getHmacJavaAlgorithm()
    {
        return hmacJavaAlgorithm;
    }

    public void setHmacJavaAlgorithm(String hmacJavaAlgorithm)
    {
        this.hmacJavaAlgorithm = hmacJavaAlgorithm;
    }

    public int getTagTruncationLength()
    {
        return tagTruncationLength;
    }

    public void setTagTruncationLength(int tagTruncationLength)
    {
        this.tagTruncationLength = tagTruncationLength;
    }

    public EncryptionResult encrypt(byte[] plaintext, byte[] aad, byte[] key) throws JoseException
    {
        // The Initialization Vector (IV) used is a 128 bit value generated
        //       randomly or pseudorandomly for use in the cipher.
        byte[] iv = ByteUtil.randomBytes(16);
        return encrypt(plaintext, aad, key, iv);
    }

    JsonWebEncryptionContentEncryptionAlgorithm.EncryptionResult encrypt(byte[] plaintext, byte[] aad, byte[] key, byte[] iv) throws JoseException
    {
        Key hmacKey = new HmacKey(ByteUtil.leftHalf(key));
        Key encryptionKey = new AesKey(ByteUtil.rightHalf(key));

        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());

        try
        {
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }

        byte[] cipherText;
        try
        {
            cipherText = cipher.doFinal(plaintext);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new JoseException(e.toString(), e);
        }
        catch (BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }

        Mac mac = MacUtil.getInitializedMac(getHmacJavaAlgorithm(), hmacKey);

        byte[] al = getAdditionalAuthenticatedDataLengthBytes(aad);

        byte[] authenticationTagInput = ByteUtil.concat(aad, iv, cipherText, al);
        byte[] authenticationTag = mac.doFinal(authenticationTagInput);
        authenticationTag = ByteUtil.subArray(authenticationTag, 0, getTagTruncationLength()); // truncate it

        return new JsonWebEncryptionContentEncryptionAlgorithm.EncryptionResult(iv, cipherText, authenticationTag);
    }

    public byte[] decrypt(byte[] cipherText, byte[] iv, byte[] aad, byte[] tag, byte[] key) throws JoseException
    {
        byte[] al = getAdditionalAuthenticatedDataLengthBytes(aad);
        byte[] authenticationTagInput = ByteUtil.concat(aad, iv, cipherText, al);
        Key hmacKey = new HmacKey(ByteUtil.leftHalf(key));
        Mac mac = MacUtil.getInitializedMac(getHmacJavaAlgorithm(), hmacKey);
        byte[] calculatedAuthenticationTag = mac.doFinal(authenticationTagInput);
        boolean tagMatch = ByteUtil.secureEquals(tag, calculatedAuthenticationTag);
        if (!tagMatch)
        {
            throw new JoseException("... special symbol FAIL that indicates that the inputs are not authentic ...");
        }

        Key encryptionKey = new AesKey(ByteUtil.rightHalf(key));

        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());
        try
        {
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(iv));
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Invalid key for " + getJavaAlgorithm(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new JoseException(e.toString(), e);
        }
        try
        {
            return cipher.doFinal(cipherText);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new JoseException(e.toString(), e);
        }
        catch (BadPaddingException e)
        {
            throw new JoseException(e.toString(), e);
        }
    }

    private byte[] getAdditionalAuthenticatedDataLengthBytes(byte[] additionalAuthenticatedData)
    {
        // The octet string AL is equal to the number of bits in associated data A expressed
        //       as a 64-bit unsigned integer in network byte order.
        long aadLength = ByteUtil.bitLength(additionalAuthenticatedData);
        return ByteUtil.getBytes(aadLength);
    }
}
