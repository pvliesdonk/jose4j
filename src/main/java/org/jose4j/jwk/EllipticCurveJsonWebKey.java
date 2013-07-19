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
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Map;

/**
 */
public class EllipticCurveJsonWebKey extends PublicJsonWebKey
{
    public static final String KEY_TYPE = "EC";

    public static final String CURVE_MEMBER_NAME = "crv";

    public static final String X_MEMBER_NAME = "x";
    public static final String Y_MEMBER_NAME = "y";

    public static final String PRIVATE_KEY_MEMBER_NAME = "d";

    private String curveName;

    public EllipticCurveJsonWebKey(ECPublicKey publicKey)
    {
        super(publicKey);
        ECParameterSpec spec = publicKey.getParams();
        EllipticCurve curve = spec.getCurve();
        curveName = EllipticCurves.getName(curve);
    }

    public EllipticCurveJsonWebKey(Map<String, Object> params) throws JoseException
    {
        super(params);

        curveName = JsonHelp.getString(params, CURVE_MEMBER_NAME);
        ECParameterSpec curve = EllipticCurves.getSpec(curveName);

        String b64x = JsonHelp.getString(params, X_MEMBER_NAME);
        BigInteger x = BigEndianBigInteger.fromBase64Url(b64x);

        String b64y = JsonHelp.getString(params, Y_MEMBER_NAME);
        BigInteger y = BigEndianBigInteger.fromBase64Url(b64y);

        EcKeyUtil keyUtil = new EcKeyUtil();

        publicKey = keyUtil.publicKey(x, y, curve);
        key = publicKey;

        if (params.containsKey(PRIVATE_KEY_MEMBER_NAME))
        {
            String b64d = JsonHelp.getString(params, PRIVATE_KEY_MEMBER_NAME);
            BigInteger d = BigEndianBigInteger.fromBase64Url(b64d);
            privateKey = keyUtil.privateKey(d, curve);
        }
    }

    public ECPublicKey getECPublicKey()
    {
        return (ECPublicKey) publicKey;
    }

    public ECPrivateKey getEcPrivateKey()
    {
        return (ECPrivateKey) privateKey;
    }

    public String getKeyType()
    {
        return KEY_TYPE;
    }

    public String getCurveName()
    {
        return curveName;
    }

    protected void fillTypeSpecificParams(Map<String, Object> params)
    {
        ECPublicKey ecPublicKey = getECPublicKey();

        ECPoint w = ecPublicKey.getW();

        BigInteger x = w.getAffineX();
        String b64x = BigEndianBigInteger.toBase64Url(x);
        params.put(X_MEMBER_NAME, b64x);

        BigInteger y = w.getAffineY();
        String b64y = BigEndianBigInteger.toBase64Url(y);
        params.put(Y_MEMBER_NAME, b64y);

        params.put(CURVE_MEMBER_NAME, getCurveName());

        if (writeOutPrivateKeyToJson)
        {
            ECPrivateKey ecPrivateKey = getEcPrivateKey();
            BigInteger s = ecPrivateKey.getS();
            String b64s = BigEndianBigInteger.toBase64Url(s);
            params.put(PRIVATE_KEY_MEMBER_NAME, b64s);
        }
    }
}
