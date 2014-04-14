package org.jose4j.jwe;

/**
 *
 */
public class Aes192GcmContentEncryptionAlgorithm extends AesGcmContentEncryptionAlgorithm
{
    public Aes192GcmContentEncryptionAlgorithm()
    {
        super(ContentEncryptionAlgorithmIdentifiers.AES_192_GCM, 192);
    }
}
