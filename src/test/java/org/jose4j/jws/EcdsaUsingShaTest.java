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

import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.lang.JoseException;

import java.security.*;

import junit.framework.TestCase;

/**
 */
public class EcdsaUsingShaTest extends TestCase
{
    EcKeyUtil keyUtil = new EcKeyUtil();

    public void testP256RoundTripGenKeys() throws JoseException
    {
        KeyPair keyPair1 = keyUtil.generateKeyPair(EllipticCurves.P_256);
        KeyPair keyPair2 = keyUtil.generateKeyPair(EllipticCurves.P_256);
        String algo = AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
        PrivateKey priv1 = keyPair1.getPrivate();
        PublicKey pub1 = keyPair1.getPublic();
        PrivateKey priv2 = keyPair2.getPrivate();
        PublicKey pub2 = keyPair2.getPublic();
        JwsTestSupport.testBasicRoundTrip("PAYLOAD!!!", algo, priv1, pub1, priv2, pub2);
    }

    public void testP384RoundTripGenKeys() throws JoseException
    {
        KeyPair keyPair1 = keyUtil.generateKeyPair(EllipticCurves.P_384);
        KeyPair keyPair2 = keyUtil.generateKeyPair(EllipticCurves.P_384);
        String algo = AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384;
        PrivateKey priv1 = keyPair1.getPrivate();
        PublicKey pub1 = keyPair1.getPublic();
        PrivateKey priv2 = keyPair2.getPrivate();
        PublicKey pub2 = keyPair2.getPublic();
        JwsTestSupport.testBasicRoundTrip("The umlaut ( /??mla?t/ uum-lowt) refers to a sound shift.", algo, priv1, pub1, priv2, pub2);
    }

    public void testP521RoundTripGenKeys() throws JoseException
    {
        KeyPair keyPair1 = keyUtil.generateKeyPair(EllipticCurves.P_521);
        KeyPair keyPair2 = keyUtil.generateKeyPair(EllipticCurves.P_521);
        String algo = AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;
        PrivateKey priv1 = keyPair1.getPrivate();
        PublicKey pub1 = keyPair1.getPublic();
        PrivateKey priv2 = keyPair2.getPrivate();
        PublicKey pub2 = keyPair2.getPublic();
        JwsTestSupport.testBasicRoundTrip("?????", algo, priv1, pub1, priv2, pub2);
    }

    public void testP256RoundTripExampleKeysAndGenKeys() throws JoseException
    {
        String algo = AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256;
        PrivateKey priv1 = ExampleEcKeysFromJws.PRIVATE_256;
        PublicKey pub1 = ExampleEcKeysFromJws.PUBLIC_256;
        KeyPair keyPair = keyUtil.generateKeyPair(EllipticCurves.P_256);
        PrivateKey priv2 = keyPair.getPrivate();
        PublicKey pub2 = keyPair.getPublic();
        JwsTestSupport.testBasicRoundTrip("something here", algo, priv1, pub1, priv2, pub2);
    }

    public void testP521RoundTripExampleKeysAndGenKeys() throws JoseException
    {
        String algo = AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;
        PrivateKey priv1 = ExampleEcKeysFromJws.PRIVATE_521;
        PublicKey pub1 = ExampleEcKeysFromJws.PUBLIC_521;
        KeyPair keyPair = keyUtil.generateKeyPair(EllipticCurves.P_521);
        PrivateKey priv2 = keyPair.getPrivate();
        PublicKey pub2 = keyPair.getPublic();
        JwsTestSupport.testBasicRoundTrip("touché", algo, priv1, pub1, priv2, pub2);
    }
}
