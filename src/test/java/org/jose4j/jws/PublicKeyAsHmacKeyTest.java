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

package org.jose4j.jws;

import org.apache.commons.logging.LogFactory;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.PublicKey;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 *
 */
public class PublicKeyAsHmacKeyTest
{
    @Test
    public void tryPubKeyAsHmacTrick() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setPayload("tardier toothache");
        jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        verify(ExampleRsaKeyFromJws.PUBLIC_KEY, jws.getCompactSerialization(), true);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setPayload("http://watchout4snakes.com/wo4snakes/Random/RandomPhrase");
        jws.setKey(new HmacKey(ExampleRsaKeyFromJws.PUBLIC_KEY.getEncoded()));
        verify(ExampleRsaKeyFromJws.PUBLIC_KEY, jws.getCompactSerialization(), false);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setPayload("salty slop");
        jws.setKey(new SecretKeySpec(ExampleRsaKeyFromJws.PUBLIC_KEY.getEncoded(), "algorithm"));
        verify(ExampleRsaKeyFromJws.PUBLIC_KEY, jws.getCompactSerialization(), false);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setPayload("flammable overture");
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        verify(ExampleEcKeysFromJws.PUBLIC_256, jws.getCompactSerialization(), true);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setPayload("scrupulous undercut");
        jws.setKey(new HmacKey(ExampleEcKeysFromJws.PRIVATE_256.getEncoded()));
        verify(ExampleEcKeysFromJws.PUBLIC_256, jws.getCompactSerialization(), false);

        jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setPayload("menial predestination");
        jws.setKey(new SecretKeySpec(ExampleEcKeysFromJws.PRIVATE_256.getEncoded(), ""));
        verify(ExampleEcKeysFromJws.PUBLIC_256, jws.getCompactSerialization(), false);
    }

    private void verify(PublicKey verificationKey, String cs, boolean expectedSignatureStatus) throws JoseException
    {
        JsonWebSignature consumerJws = new JsonWebSignature();
        consumerJws.setDoKeyValidation(false); // check even with this being lax
        consumerJws.setCompactSerialization(cs);
        consumerJws.setKey(verificationKey);
        try
        {
            assertThat(consumerJws.verifySignature(), equalTo(expectedSignatureStatus));
        }
        catch (JoseException e)
        {
            LogFactory.getLog(this.getClass()).debug(ExceptionHelp.toStringWithCauses(e));
            assertFalse("expected valid signature but got " + e, expectedSignatureStatus);
        }
    }
}
