package org.jose4j.jwe;

/**
 */
public class Aes256KeyWrapManagementAlgorithm extends AesKeyWrapManagementAlgorithm
{
    public Aes256KeyWrapManagementAlgorithm()
    {
        super(KeyManagementAlgorithmIdentifiers.A256KW);
    }
}