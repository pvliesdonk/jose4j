package org.jose4j.jws;

/**
 */
public class HmacUsingSha384Algorithm extends HmacUsingShaAlgorithm
{
    public HmacUsingSha384Algorithm()
    {
        super(AlgorithmIdentifiers.HMAC_SHA384, "HmacSHA384");
    }
}