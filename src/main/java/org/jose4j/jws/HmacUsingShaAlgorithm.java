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
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.keys.KeyType;
import org.jose4j.keys.HmacKey;

import javax.crypto.Mac;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 */
public class HmacUsingShaAlgorithm extends AlgorithmInfo implements JsonWebSignatureAlgorithm
{
    public HmacUsingShaAlgorithm(String id, String javaAlgo)
    {
        setAlgorithmIdentifier(id);
        setJavaAlgorithm(javaAlgo);
        setKeyType(KeyType.SYMMETRIC);
        setKeyAlgorithm(HmacKey.ALGORITHM);
    }

    public boolean verifySignature(byte[] signatureBytes, Key key, byte[] securedInputBytes) throws JoseException
    {
        Mac mac = getMacInstance();
        initMacWithKey(mac, key);
        byte[] calculatedSigature = mac.doFinal(securedInputBytes);

        return ByteUtil.secureEquals(signatureBytes, calculatedSigature);
    }

    public byte[] sign(Key key, byte[] securedInputBytes) throws JoseException
    {
        Mac mac = getMacInstance();
        initMacWithKey(mac, key);
        return mac.doFinal(securedInputBytes);
    }

    private void initMacWithKey(Mac mac, Key key) throws JoseException
    {
        try
        {
            mac.init(key);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Key is not valid for " + getJavaAlgorithm(), e);
        }
    }

    private Mac getMacInstance() throws JoseException
    {
        Mac mac;

        try
        {
            mac = Mac.getInstance(getJavaAlgorithm());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new JoseException("Unable to get an implementation of algorithm name: " + getJavaAlgorithm(), e);
        }

        return /* of the */ mac;
    }


}
