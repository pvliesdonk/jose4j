/*
 * Copyright 2012-2013 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.JoseException;

import java.security.*;

/**
 */
public abstract class BaseSignatureAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    public BaseSignatureAlgorithm(String id, String javaAlgo, String keyAlgo)
    {
        setAlgorithmIdentifier(id);
        setJavaAlgorithm(javaAlgo);
        setKeyPersuasion(KeyPersuasion.ASYMMETRIC);
        setKeyType(keyAlgo);
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
        catch (InvalidKeyException e)
        {
            throw new JoseException(getBadKeyMessage(key) + "for " + getJavaAlgorithm(), e);
        }
    }

    private void initForVerify(Signature signature, Key key) throws JoseException
    {
        try
        {
           PublicKey publicKey = (PublicKey) key;
           signature.initVerify(publicKey);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException(getBadKeyMessage(key) + "for " + getJavaAlgorithm(), e);
        }
    }

    private String getBadKeyMessage(Key key)
    {
        String msg = key == null ? "key is null" : "algorithm=" + key.getAlgorithm();
        return "The given key (" + msg + ") is not valid ";
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

    public abstract void validatePrivateKey(PrivateKey privateKey) throws JoseException;

    public void validateSigningKey(Key key) throws JoseException
    {
        try
        {
            validatePrivateKey((PrivateKey)key);
        }
        catch (ClassCastException e)
        {
            throw new JoseException(getBadKeyMessage(key) + "(not a private key or is the wrong type of key) for " + getJavaAlgorithm() + "/" + getAlgorithmIdentifier() + " " +  e);
        }
    }

    public abstract void validatePublicKey(PublicKey publicKey) throws JoseException;

    public void validateVerificationKey(Key key) throws JoseException
    {
        checkForNullKey(key);

        try
        {
            validatePublicKey((PublicKey)key);
        }
        catch (ClassCastException e)
        {
            throw new JoseException(getBadKeyMessage(key) + "(not a public key or is the wrong type of key) for " + getJavaAlgorithm() + "/" + getAlgorithmIdentifier() + " " +  e);
        }
    }

    private void checkForNullKey(Key key) throws JoseException
    {
        if (key == null)
        {
            throw new JoseException("Key cannot be null");
        }
    }
}
