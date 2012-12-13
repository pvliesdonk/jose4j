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

import org.jose4j.lang.JoseException;
import org.jose4j.keys.ExampleEcKeysFromJws;
import junit.framework.TestCase;

/**
 */
public class JwsUsingEcdsaP521Sha512ExampleTest extends TestCase
{
    String JWS = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";

    public void testVerifyExample() throws JoseException
    {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(JWS);
        jws.setKey(ExampleEcKeysFromJws.PUBLIC_521);
        assertTrue("signature should validate", jws.verifySignature());
    }
}
