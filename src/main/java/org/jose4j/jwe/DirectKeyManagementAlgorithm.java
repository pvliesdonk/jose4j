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
        // todo check managementKey against cekDesc... ?
        byte[] cekBytes = managementKey.getEncoded();
        return new ContentEncryptionKeys(cekBytes, null);
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers) throws JoseException
    {
        // todo check encryptedKey is empty
        // todo check cekDesc against managment key
        return managementKey;
    }

    @Override
    public void validateEncryptionKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
        validateKey(managementKey, contentEncryptionAlg);
    }

    private void validateKey(Key managementKey, ContentEncryptionAlgorithm contentEncryptionAlg) throws JoseException
    {
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
