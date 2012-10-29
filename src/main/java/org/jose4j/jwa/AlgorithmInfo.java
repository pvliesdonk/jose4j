package org.jose4j.jwa;

import org.jose4j.keys.KeyType;

/**
 */
public abstract class AlgorithmInfo
{
    private String algorithmIdentifier;
    private String javaAlgorithm;
    private KeyType keyType;
    private String keyAlgorithm;

    public void setAlgorithmIdentifier(String algorithmIdentifier)
    {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public void setJavaAlgorithm(String javaAlgorithm)
    {
        this.javaAlgorithm = javaAlgorithm;
    }

    public String getJavaAlgorithm()
    {
        return javaAlgorithm;
    }

    public String getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public KeyType getKeyType()
    {
        return keyType;
    }

    public void setKeyType(KeyType keyType)
    {
        this.keyType = keyType;
    }

    public String getKeyAlgorithm()
    {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm)
    {
        this.keyAlgorithm = keyAlgorithm;
    }
}
