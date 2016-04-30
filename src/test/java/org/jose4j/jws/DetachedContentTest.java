/*
 * Copyright 2012-2016 Brian Campbell
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

import org.jose4j.keys.ExampleEcKeysFromJws;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 *
 */
public class DetachedContentTest
{
    @Test
    public void testSomeDetachedContent() throws Exception
    {
        String payload = "Issue #48";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(ExampleEcKeysFromJws.PRIVATE_256);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        String detachedContentCompactSerialization = jws.getDetachedContentCompactSerialization();
        String encodedPayload = jws.getEncodedPayload();
        String compactSerialization = jws.getCompactSerialization();

        jws = new JsonWebSignature();
        jws.setCompactSerialization(detachedContentCompactSerialization);
        jws.setEncodedPayload(encodedPayload);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));

        jws = new JsonWebSignature();
        jws.setCompactSerialization(compactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertTrue(jws.verifySignature());
        assertThat(payload, equalTo(jws.getPayload()));

        jws = new JsonWebSignature();
        jws.setCompactSerialization(detachedContentCompactSerialization);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_256);
        assertFalse(jws.verifySignature());
    }
}
