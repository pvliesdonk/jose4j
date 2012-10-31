/*
 * Copyright 2012 Brian Campbell
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
import org.jose4j.keys.KeyType;
import org.jose4j.keys.RsaKeyUtil;
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
        setKeyAlgorithm(RsaKeyUtil.RSA);
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
            throw new JoseException(getBadKeyMessage(key) + "(not a private key) for " + getJavaAlgorithm() + " " + e);
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
        catch (ClassCastException e)
        {
            throw new JoseException(getBadKeyMessage(key) + "(not a public key) for " + getJavaAlgorithm() + " " +  e);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException(getBadKeyMessage(key) + "for " + getJavaAlgorithm(), e);
        }
    }

    private String getBadKeyMessage(Key key)
    {
        return "The given key (algorithm="+key.getAlgorithm()+") is not valid ";
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
