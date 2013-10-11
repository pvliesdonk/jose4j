package org.jose4j.jwe;

/**
 */
public class Rsa1_5KeyManagementAlgorithm extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
{
    public Rsa1_5KeyManagementAlgorithm()
    {
        super("RSA/ECB/PKCS1Padding", KeyManagementAlgorithmIdentifiers.RSA1_5);

    }
}
