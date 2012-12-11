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

import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.math.BigInteger;

/**
 * example EC keys from http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
 */
public class ExampleEcKeysFromJws
{
    // The ECDSA key consists of a public part, the EC point (x, y)
    public static final int[] X_INTS_256 = {127, 205, 206, 39, 112, 246, 196, 93, 65, 131, 203,
      238, 111, 219, 75, 123, 88, 7, 51, 53, 123, 233, 239,
      19, 186, 207, 110, 60, 123, 209, 84, 69};
    public static final int[] Y_INTS_256 =  {199, 241, 68, 205, 27, 189, 155, 126, 135, 44, 223,
        237, 185, 238, 185, 244, 179, 105, 93, 110, 169, 11,
        36, 173, 138, 70, 35, 40, 133, 136, 229, 173};

    // and a private part d.
    public static final int[] D_INTS_256 = {142, 155, 16, 158, 113, 144, 152, 191, 152, 4, 135,
       223, 31, 93, 119, 233, 203, 41, 96, 110, 190, 210,
       38, 59, 95, 87, 194, 19, 223, 132, 244, 178};

    public static final byte[] X_BYTES_256 = ByteUtil.convertUnsignedToSignedTwosComp(X_INTS_256);
    public static final byte[] Y_BYTES_256 = ByteUtil.convertUnsignedToSignedTwosComp(Y_INTS_256);
    public static final byte[] D_BYTES_256 = ByteUtil.convertUnsignedToSignedTwosComp(D_INTS_256);

    public static final BigInteger X = BigEndianBigInteger.fromBytes(X_BYTES_256);
    public static final BigInteger Y = BigEndianBigInteger.fromBytes(Y_BYTES_256);
    public static final BigInteger D = BigEndianBigInteger.fromBytes(D_BYTES_256);


    public static final ECPrivateKey PRIVATE_256;
    public static final ECPublicKey PUBLIC_256;

    static
    {
        EcKeyUtil ecKeyUtil = new EcKeyUtil();

        try
        {
            PRIVATE_256 = ecKeyUtil.privateKey(D, EllipticCurves.P_256);
            PUBLIC_256 = ecKeyUtil.publicKey(X, Y, EllipticCurves.P_256);
        }
        catch (JoseException e)
        {
            throw new IllegalStateException(e.getMessage(),e);
        }
    }
}

