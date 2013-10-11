package org.jose4j.jwe;

import org.jose4j.keys.AesKey;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.security.Key;

/**
 */
public class AesKeyWrapManagementAlgorithm extends WrappingKeyManagementAlgorithm
{
    int keyByteLength;

    public AesKeyWrapManagementAlgorithm(String alg, int keyByteLength)
    {
        super("AESWrap", alg);
        setKeyType(AesKey.ALGORITHM);
        setKeyPersuasion(KeyPersuasion.SYMMETRIC);
        this.keyByteLength = keyByteLength;
    }

    int getKeyByteLength()
    {
        return keyByteLength;
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey);
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey);
    }

    void validateKey(Key managementKey) throws JoseException
    {

        String alg = managementKey.getAlgorithm();

        if (!AesKey.ALGORITHM.equals(alg))
        {
            throw new JoseException("Invalid key for JWE " + getAlgorithmIdentifier() + ", expected an "
                               + AesKey.ALGORITHM+ " key but an " + alg + " bit key was provided.");
        }

        int managementKeyByteLength = managementKey.getEncoded().length;
        if (managementKeyByteLength != getKeyByteLength())
        {
           throw new JoseException("Invalid key for JWE " + getAlgorithmIdentifier() + ", expected a "
                   + ByteUtil.bitLength(getKeyByteLength())+ " bit key but a "
                   + ByteUtil.bitLength(managementKeyByteLength) + " bit key was provided.");
        }
    }
}
