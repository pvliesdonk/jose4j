package org.jose4j.jwe;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.JoseException;

import java.security.Key;

/**
 */
public class DirectKeyManagementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    private static final byte[] EMPTY_OCTET_SEQUENCE = new byte[]{};

    public DirectKeyManagementAlgorithm()
    {
        setAlgorithmIdentifier(KeyManagementAlgorithmIdentifiers.DIRECT);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc) throws JoseException
    {
        // todo check managementKey against cekDesc... ?
        byte[] cekBytes = managementKey.getEncoded();
        return new ContentEncryptionKeys(cekBytes, EMPTY_OCTET_SEQUENCE);
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc) throws JoseException
    {
        // todo check encryptedKey is empty
        // todo check cekDesc against managment key
        return managementKey;
    }
}
