package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.ByteUtil;
import org.jose4j.keys.KeyType;

import java.security.Key;

/**
 */
public class PlaintextNoneAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    private static final String ILLEGAL_STATE_MSG = "JWS Plaintext ("+ HeaderParameterNames.ALGORITHM+"="+ AlgorithmIdentifiers.NONE+") must not use a key.";

    public PlaintextNoneAlgorithm()
    {
        setAlgorithmIdentifier(AlgorithmIdentifiers.NONE);
        setKeyType(KeyType.NONE);
    }

    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes)
    {
        if (key != null)
        {
            throw new IllegalStateException(ILLEGAL_STATE_MSG);
        }

        return (signatureBytes.length == 0);
    }

    public byte[] sign(Key key, byte[] securedInputBytes)
    {
        if (key != null)
        {
            throw new IllegalStateException(ILLEGAL_STATE_MSG);
        }

        return ByteUtil.EMPTY_BYTES;
    }
}
