package org.jose4j.jwe;

/**
 */
public class RsaOaepKeyManagementAlgorithm extends RsaKeyManagementAlgorithm implements KeyManagementAlgorithm
{
    public RsaOaepKeyManagementAlgorithm()
    {
        // and todo actually need to see if this works or if more needs to be done
        // and todo does the gen random key thing need to happen with OAEP or just for 1_5?
        super("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", KeyManagementAlgorithmIdentifiers.RSA_OAEP);   // or RSA/ECB/OAEPPadding and params todo?
    }
}
