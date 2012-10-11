package org.jose4j.jws;

import org.jose4j.jwa.Algorithm;
import org.jose4j.keys.KeyType;

import java.security.Key;

/**
 */
public interface JsonWebSignatureAlgorithm extends Algorithm
{
    boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes);
    byte[] sign(Key key, byte[] securedInputBytes);
}
