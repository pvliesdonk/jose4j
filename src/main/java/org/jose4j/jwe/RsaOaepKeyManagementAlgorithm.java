package org.jose4j.jwe;

/**
 */
public class RsaOaepKeyManagementAlgorithm extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
{
    public RsaOaepKeyManagementAlgorithm()
    {
        super("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", KeyManagementAlgorithmIdentifiers.RSA_OAEP);
    }
}
