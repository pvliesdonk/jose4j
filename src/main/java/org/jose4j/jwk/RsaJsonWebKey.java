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

package org.jose4j.jwk;

import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 */
public class RsaJsonWebKey extends JsonWebKey
{
    public static final String MODULUS_MEMBER_NAME = "n";
    public static final String EXPONENT_MEMBER_NAME = "e";

    public static final String KEY_TYPE = "RSA";

    public RsaJsonWebKey(RSAPublicKey publicKey)
    {
        super(publicKey);
    }

    public RsaJsonWebKey(Map<String, Object> params) throws JoseException
    {
        super(params);
        String b64Modulus = JsonHelp.getString(params, MODULUS_MEMBER_NAME);
        BigInteger modulus = BigEndianBigInteger.fromBase64Url(b64Modulus);

        String b64Exponent = JsonHelp.getString(params, EXPONENT_MEMBER_NAME);
        BigInteger publicExponent = BigEndianBigInteger.fromBase64Url(b64Exponent);

        RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
        publicKey = rsaKeyUtil.publicKey(modulus, publicExponent);
    }

    public String getKeyType()
    {
        return KEY_TYPE;
    }

    public RSAPublicKey getRSAPublicKey()
    {
        return (RSAPublicKey)publicKey;
    }

    protected void fillTypeSpecificParams(Map<String, Object> params)
    {
        RSAPublicKey rsaPublicKey = getRSAPublicKey();
        BigInteger modulus = rsaPublicKey.getModulus();
        String b64Modulus = BigEndianBigInteger.toBase64Url(modulus);
        params.put(MODULUS_MEMBER_NAME, b64Modulus);

        BigInteger publicExponent = rsaPublicKey.getPublicExponent();
        String b64Exponent = BigEndianBigInteger.toBase64Url(publicExponent);
        params.put(EXPONENT_MEMBER_NAME, b64Exponent);
    }
}
