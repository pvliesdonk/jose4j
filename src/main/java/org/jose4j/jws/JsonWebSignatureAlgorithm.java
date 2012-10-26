package org.jose4j.jws;

import org.jose4j.jwa.Algorithm;
import org.jose4j.keys.KeyType;
import org.jose4j.lang.JoseException;

import java.security.Key;

/**
 */
public interface JsonWebSignatureAlgorithm extends Algorithm
{
    boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes) throws JoseException;
    byte[] sign(Key key, byte[] securedInputBytes) throws JoseException ;
}
