package org.jose4j.jws;

/**
 */
public class RsaUsingSha512Algorithm extends RsaUsingShaAlgorithm
{
    public RsaUsingSha512Algorithm()
    {
        super(AlgorithmIdentifiers.RSA_USING_SHA512, "SHA512withRSA");
    }
}