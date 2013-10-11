package org.jose4j.jwe;

import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.keys.KeyPersuasion;

/**
 */
public class RsaKeyManagementAlgorithm extends WrappingKeyManagementAlgorithm implements KeyManagementAlgorithm
{
    public RsaKeyManagementAlgorithm(String javaAlg, String alg)
    {
        super(javaAlg, alg);
        setKeyType(RsaJsonWebKey.KEY_TYPE);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
    }
}
