package org.jose4j.jwe;

/**
 *
 */
public class Aes128GcmContentEncryptionAlgorithm extends AesGcmContentEncryptionAlgorithm
{
    public Aes128GcmContentEncryptionAlgorithm()
    {
        super(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, 128);
    }
}
