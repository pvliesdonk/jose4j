package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.security.Key;

/**
 */
public class DirectKeyManagementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    public DirectKeyManagementAlgorithm()
    {
        setAlgorithmIdentifier(KeyManagementAlgorithmIdentifiers.DIRECT);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers) throws JoseException
    {
        byte[] cekBytes = managementKey.getEncoded();
        return new ContentEncryptionKeys(cekBytes, ByteUtil.EMPTY_BYTES);
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers) throws JoseException
    {
        if (encryptedKey.length != 0)
        {
            throw new JoseException("An empty octet sequence is used as the JWE Encrypted Key value when utilizing " +
                    "direct encryption but this JWE has " + encryptedKey.length + " octets in the encrypted key part.");
        }
        return managementKey;
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey, contentEncryptionAlg);
    }

    private void validateKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        if (managementKey == null)
        {
            throw new JoseException("The key must not be null.");
        }

        int managementKeyByteLength = managementKey.getEncoded().length;
        int expectedByteLength = contentEncryptionAlg.getContentEncryptionKeyDescriptor().getContentEncryptionKeyByteLength();
        if (expectedByteLength != managementKeyByteLength)
        {
            throw new JoseException("Invalid key for " + getAlgorithmIdentifier() + " with "
                              + contentEncryptionAlg.getAlgorithmIdentifier() +", expected a "
                              + ByteUtil.bitLength(expectedByteLength)+ " bit key but a "
                              + ByteUtil.bitLength(managementKeyByteLength) + " bit key was provided.");
        }
    }

    @Override
    public void validateDecryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey, contentEncryptionAlg);
    }
}
