package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.keys.KeyType;
import org.jose4j.lang.JoseException;

import java.security.*;

/**
 */
public class RsaUsingShaAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    public RsaUsingShaAlgorithm(String id, String javaAlgo)
    {
        setAlgorithmIdentifier(id);
        setJavaAlgorithm(javaAlgo);
        setKeyType(KeyType.ASYMMETRIC);
    }

    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes) throws JoseException
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
            throw new JoseException("Problem verifying signature.", e);
        }
    }

    public byte[] sign(Key key, byte[] securedInputBytes) throws JoseException
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
            throw new JoseException("Problem creating signature.", e);
        }
    }

    private void initForSign(Signature signature, Key key) throws JoseException
    {
        try
        {
            PrivateKey privateKey = (PrivateKey) key;
            signature.initSign(privateKey);
        }
        catch (ClassCastException e)
        {
            throw new JoseException("Key is not valid (not a private key) for " + getJavaAlgorithm() + " " + e);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Key is not valid for " + getJavaAlgorithm(), e);
        }
    }
    
    private void initForVerify(Signature signature, Key key) throws JoseException
    {
        try
        {
           PublicKey publicKey = (PublicKey) key;
           signature.initVerify(publicKey);
        }
        catch (ClassCastException e)
        {
            throw new JoseException("Key is not valid (not a public key) for " + getJavaAlgorithm() + " " +  e);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Key is not valid for " + getJavaAlgorithm(), e);
        }
    }

    private Signature getSignature() throws JoseException
    {
        try
        {
            return Signature.getInstance(getJavaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Unable to get an implementation of algorithm name: " + getJavaAlgorithm(), e);
        }
    }
}
