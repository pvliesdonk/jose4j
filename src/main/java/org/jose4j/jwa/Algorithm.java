package org.jose4j.jwa;

import org.jose4j.keys.KeyType;

/**
 */
public interface Algorithm
{
    String getJavaAlgorithm();
    String getAlgorithmIdentifier();
    KeyType getKeyType();    
}
