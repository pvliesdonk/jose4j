/*
 * Copyright 2012-2015 Brian Campbell
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
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;

/**
 */
abstract class KeyPairUtil
{
    public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    abstract String getAlgorithm();

    protected KeyFactory getKeyFactory() throws JoseException
    {
        try
        {
            return KeyFactory.getInstance(getAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Couldn't find " + getAlgorithm() + " KeyFactory! " + e, e);
        }
    }

    protected KeyPairGenerator getKeyPairGenerator() throws JoseException
    {
        try
        {
            return KeyPairGenerator.getInstance(getAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Couldn't find " + getAlgorithm() + " KeyPairGenerator! " + e, e);
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
