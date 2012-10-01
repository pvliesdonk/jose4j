package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 */
public class Aes128CbcSymmetricEncryptionAlgorithm extends AlgorithmInfo implements SymmetricEncryptionAlgorithm
{
    public Aes128CbcSymmetricEncryptionAlgorithm()
    {
        setAlgorithmIdentifier(SymmetricEncryptionAlgorithmIdentifiers.A128CBC);
        setJavaAlgorithm("AES/CBC/PKCS5Padding");
    }

    public int getKeySize()
    {
        return 128;
    }

    public boolean isAead()
    {
        return false;
    }

    public Result encrypt(byte[] plaintext, byte[] key)
    {
        return null;
//        Cipher cipher = getCipher();
//        SecretKeySpec spec = new SecretKeySpec(key, "AES");
//        ??? or make key elsewhere?
//        cipher.init(Cipher.ENCRYPT_MODE, );

    }

    private Cipher getCipher()
    {
        try
        {
            return Cipher.getInstance(getJavaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException(e.toString() , e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new IllegalStateException(e.toString() , e);
        }
    }
}
