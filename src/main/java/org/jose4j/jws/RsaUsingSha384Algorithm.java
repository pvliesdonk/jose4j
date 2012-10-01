package org.jose4j.jws;

/**
 */
public class RsaUsingSha384Algorithm extends RsaUsingShaAlgorithm
{
    public RsaUsingSha384Algorithm()
    {
        super(AlgorithmIdentifiers.RSA_USING_SHA384, "SHA384withRSA");
    }
}