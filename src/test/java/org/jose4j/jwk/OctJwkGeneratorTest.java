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

package org.jose4j.jwk;

import junit.framework.TestCase;
import org.jose4j.lang.ByteUtil;

import javax.crypto.SecretKey;

/**
 */
public class OctJwkGeneratorTest extends TestCase
{
    public void testGen()
    {
        for (int size : new int[]{128, 192, 256, 192, 384, 512})
        {
            OctetSequenceJsonWebKey jsonWebKey = OctJwkGenerator.generateJwk(size);
            assertNotNull(jsonWebKey.getKey());
            assertTrue(jsonWebKey.getKey() instanceof SecretKey);
            assertEquals(ByteUtil.byteLength(size), jsonWebKey.getOctetSequence().length);
        }
    }
}
