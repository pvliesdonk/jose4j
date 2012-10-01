package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmInfo;

import java.security.*;

/**
 */
public class RsaUsingShaAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    public RsaUsingShaAlgorithm(String id, String javaAlgo)
    {
        setAlgorithmIdentifier(id);
        setJavaAlgorithm(javaAlgo);
    }

    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes)
    {
        Signature signature = getSignature();
        initForVerify(signature, key);
        try
        {
            signature.update(securedInputBytes);
            return signature.verify(signatureBytes);
        }
        catch (SignatureException e)
        {
            throw new IllegalStateException("Problem verifying signature.", e);
        }
    }

    public byte[] sign(Key key, byte[] securedInputBytes)
    {
        Signature signature = getSignature();
        initForSign(signature, key);
        try
        {
            signature.update(securedInputBytes);
            return signature.sign();
        }
        catch (SignatureException e)
        {
            throw new IllegalStateException("Problem creating signature.", e);
        }
    }

    private void initForSign(Signature signature, Key key)
    {
        try
        {
            PrivateKey privateKey = (PrivateKey) key;
            signature.initSign(privateKey);
        }
        catch (ClassCastException e)
        {
            throw new IllegalStateException("Key is not valid (not a private key) for " + getJavaAlgorithm(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalStateException("Key is not valid for " + getJavaAlgorithm(), e);
        }
    }
    
    private void initForVerify(Signature signature, Key key)
    {
        try
        {
           PublicKey publicKey = (PublicKey) key;
           signature.initVerify(publicKey);
        }
        catch (ClassCastException e)
        {
            throw new IllegalStateException("Key is not valid (not a public key) for " + getJavaAlgorithm(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalStateException("Key is not valid for " + getJavaAlgorithm(), e);
        }
    }

    private Signature getSignature()
    {
        try
        {
            return Signature.getInstance(getJavaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Unable to get an implementation of algorithm name: " + getJavaAlgorithm(), e);
        }
    }
}
