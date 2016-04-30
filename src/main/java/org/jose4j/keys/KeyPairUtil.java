/*
 * Copyright 2012-2016 Brian Campbell
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

import org.jose4j.base64url.SimplePEMEncoder;
import org.jose4j.lang.JoseException;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;

/**
 */
abstract class KeyPairUtil
{
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    protected String provider;
    protected SecureRandom secureRandom;

    protected KeyPairUtil(String provider, SecureRandom secureRandom)
    {
        this.provider = provider;
        this.secureRandom = secureRandom;
    }

    abstract String getAlgorithm();

    protected KeyFactory getKeyFactory() throws JoseException
    {
        String agl = getAlgorithm();
        try
        {
            return provider == null ? KeyFactory.getInstance(agl) : KeyFactory.getInstance(agl, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Couldn't find " + agl + " KeyFactory! " + e, e);
        }
        catch (NoSuchProviderException e)
        {
            throw new JoseException("Cannot get KeyFactory instance with provider " + provider, e);
        }
    }

    protected KeyPairGenerator getKeyPairGenerator() throws JoseException
    {
        String alg = getAlgorithm();
        try
        {
            return provider == null ? KeyPairGenerator.getInstance(alg) : KeyPairGenerator.getInstance(alg, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Couldn't find " + alg + " KeyPairGenerator! " + e, e);
        }
        catch (NoSuchProviderException e)
        {
            throw new JoseException("Cannot get KeyPairGenerator instance with provider " + provider, e);
        }
    }

    public PublicKey fromPemEncoded(String pem) throws JoseException, InvalidKeySpecException
    {
        int beginIndex = pem.indexOf(BEGIN_PUBLIC_KEY) + BEGIN_PUBLIC_KEY.length();
        int endIndex = pem.indexOf(END_PUBLIC_KEY);
        String base64 = pem.substring(beginIndex, endIndex).trim();
        byte[] decode = SimplePEMEncoder.decode(base64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decode);
        KeyFactory kf = getKeyFactory();
        return kf.generatePublic(spec);
    }

    public static String pemEncode(PublicKey publicKey)
    {
        byte[] encoded = publicKey.getEncoded(); // X509 SPKI
        return BEGIN_PUBLIC_KEY + "\r\n" + SimplePEMEncoder.encode(encoded) + END_PUBLIC_KEY;
    }

    public boolean isAvailable()
    {
        Set<String> keyFactories = Security.getAlgorithms("KeyFactory");
        Set<String> keyPairGenerators = Security.getAlgorithms("KeyPairGenerator");
        String algorithm = getAlgorithm();
        return keyPairGenerators.contains(algorithm) && keyFactories.contains(algorithm);
    }
}
