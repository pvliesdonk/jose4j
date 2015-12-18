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

package org.jose4j.mac;

import org.jose4j.lang.JoseException;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 */
public class MacUtil
{
    public static final String HMAC_SHA256 = "HmacSHA256";
    public static final String HMAC_SHA384 = "HmacSHA384";
    public static final String HMAC_SHA512 = "HmacSHA512";

    public static Mac getInitializedMac(String algorithm, Key key) throws JoseException
    {
        return getInitializedMac(algorithm, key, null);
    }

    public static Mac getInitializedMac(String algorithm, Key key, String provider) throws JoseException
    {
        Mac mac = getMac(algorithm, provider);
        initMacWithKey(mac, key);
        return /* of the */ mac;
    }

    public static Mac getMac(String algorithm) throws JoseException
    {
        return getMac(algorithm, null);
    }

    public static Mac getMac(String algorithm, String provider) throws JoseException
    {
        try
        {
            return provider == null ? Mac.getInstance(algorithm) : Mac.getInstance(algorithm, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Unable to get a MAC implementation of algorithm name: " + algorithm, e);
        }
        catch (NoSuchProviderException e)
        {
            throw new JoseException("Unable to get a MAC implementation of algorithm name: " + algorithm + " using provider " + provider, e);
        }
    }

    public static void initMacWithKey(Mac mac, Key key) throws org.jose4j.lang.InvalidKeyException
    {
        try
        {
            mac.init(key);
        }
        catch (InvalidKeyException e)
        {
            throw new org.jose4j.lang.InvalidKeyException("Key is not valid for " + mac.getAlgorithm(), e);
        }
    }
}
