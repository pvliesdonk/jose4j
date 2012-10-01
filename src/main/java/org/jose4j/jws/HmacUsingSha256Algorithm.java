package org.jose4j.jws;


/**
 */
public class HmacUsingSha256Algorithm extends HmacUsingShaAlgorithm
{
    public HmacUsingSha256Algorithm()
    {
        super(AlgorithmIdentifiers.HMAC_SHA256, "HmacSHA256");
    }
}
