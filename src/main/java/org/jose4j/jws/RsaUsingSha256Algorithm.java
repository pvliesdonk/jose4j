package org.jose4j.jws;

/**
 */
public class RsaUsingSha256Algorithm extends RsaUsingShaAlgorithm
{
    public RsaUsingSha256Algorithm()
    {
        super(AlgorithmIdentifiers.RSA_USING_SHA256, "SHA256withRSA");
    }
}
