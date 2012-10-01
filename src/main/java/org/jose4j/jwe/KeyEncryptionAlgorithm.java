package org.jose4j.jwe;

import org.jose4j.jwa.Algorithm;

import java.security.Key;

/**
 */
public interface KeyEncryptionAlgorithm extends Algorithm
{
    byte[] encrypt(Key key, byte[] contentMasterKey);
}
