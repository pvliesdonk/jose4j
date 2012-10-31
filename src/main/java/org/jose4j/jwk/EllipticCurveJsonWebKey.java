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

import java.util.Map;
import java.math.BigInteger;

/**
 */
public class EllipticCurveJsonWebKey extends JsonWebKey
{
    public static final String ALGORITHM_VALUE = "EC";

    public static final String CURVE_MEMBER_NAME = "crv";

    public static final String X_MEMBER_NAME = "x";
    public static final String Y_MEMBER_NAME = "y";

    private  Map<String, String> params; // TODO  just a temp thing to hold data for parsing tests 

    public EllipticCurveJsonWebKey(Map<String, String> params)
    {
        super(params);

        String curve = params.get(CURVE_MEMBER_NAME);

        String b64x = params.get(X_MEMBER_NAME);
        BigInteger x = BigEndianBigInteger.fromBase64Url(b64x);

        String b64y = params.get(Y_MEMBER_NAME);
        BigInteger y = BigEndianBigInteger.fromBase64Url(b64y);

        //TODO

        this.params = params;
    }
    
    public String getAlgorithm()
    {
        return ALGORITHM_VALUE;
    }

    protected void fillTypeSpecificParams(Map<String, String> params)
    {
        params.putAll(this.params);  // TODO
    }
}
