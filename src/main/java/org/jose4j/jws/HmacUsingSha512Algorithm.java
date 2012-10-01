package org.jose4j.jws;

/**
 */
public class HmacUsingSha512Algorithm extends HmacUsingShaAlgorithm
{
    public HmacUsingSha512Algorithm()
    {
        super(AlgorithmIdentifiers.HMAC_SHA512, "HmacSHA512");
    }
}