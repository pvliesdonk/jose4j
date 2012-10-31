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

import java.util.Map;
import java.security.interfaces.RSAPublicKey;
import java.math.BigInteger;

/**
 */
public class RsaJsonWebKey extends JsonWebKey
{
    public static final String MODULUS_MEMBER_NAME = "mod";
    public static final String EXPONENT_MEMBER_NAME = "exp";

    public static final String ALGORITHM_VALUE = "RSA";

    private RSAPublicKey publicKey;

    public RsaJsonWebKey(RSAPublicKey publicKey)
    {
        super(publicKey);
        this.publicKey = publicKey;
    }

    public RsaJsonWebKey(Map<String, String> params) throws JoseException
    {
        super(params);
        String b64Modulus = params.get(MODULUS_MEMBER_NAME);
        BigInteger modulus = BigEndianBigInteger.fromBase64Url(b64Modulus);

        String b64Exponent = params.get(EXPONENT_MEMBER_NAME);
        BigInteger publicExponent = BigEndianBigInteger.fromBase64Url(b64Exponent);

        RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
        publicKey = rsaKeyUtil.publicKey(modulus, publicExponent);
    }

    public String getAlgorithm()
    {
        return ALGORITHM_VALUE;
    }

    public RSAPublicKey getRSAPublicKey()
    {
        return publicKey;
    }

    protected void fillTypeSpecificParams(Map<String, String> params)
    {
        BigInteger modulus = publicKey.getModulus();
        String b64Modulus = BigEndianBigInteger.toBase64Url(modulus);
        params.put(MODULUS_MEMBER_NAME, b64Modulus);

        BigInteger publicExponent = publicKey.getPublicExponent();
        String b64Exponent = BigEndianBigInteger.toBase64Url(publicExponent);
        params.put(EXPONENT_MEMBER_NAME, b64Exponent);
    }
}
