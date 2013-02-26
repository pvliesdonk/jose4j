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

package org.jose4j.keys;

import org.jose4j.lang.JoseException;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 */
public class RsaKeyUtil
{
    private KeyFactory keyFactory;
    private KeyPairGenerator keyGenerator;

    public static final String RSA = "RSA";

    public RsaKeyUtil()
    {
        try
        {
            keyFactory = KeyFactory.getInstance(RSA);
            keyGenerator = KeyPairGenerator.getInstance(RSA);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Couldn't find "+ RSA + " KeyFactory and/or KeyPairGenerator!?!", e);
        }
    }

    public RSAPublicKey publicKey(BigInteger modulus, BigInteger publicExponent) throws JoseException
    {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        try
        {
            PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);
            return (RSAPublicKey) publicKey;
        }
        catch (InvalidKeySpecException e)
        {
            throw new JoseException("Invalid key spec: " + e, e);
        }
    }

    public RSAPrivateKey privateKey(BigInteger modulus, BigInteger privateExponent) throws JoseException
    {
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        try
        {
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return (RSAPrivateKey) privateKey;
        }
        catch (InvalidKeySpecException e)
        {
            throw new JoseException("Invalid key spec: " + e, e);
        }
    }

    public KeyPair generateKeyPair(int bits)
    {
        keyGenerator.initialize(bits);
        return keyGenerator.generateKeyPair();
    }
}
