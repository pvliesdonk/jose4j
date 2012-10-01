package org.jose4j.jwa;

/**
 */
public abstract class AlgorithmInfo
{
    private String algorithmIdentifier;
    private String javaAlgorithm;

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
}
