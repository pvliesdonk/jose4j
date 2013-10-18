/*
 * Copyright 2012-2013 Brian Campbell
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

package org.jose4j.jwe.kdf;

import junit.framework.TestCase;

import java.util.Arrays;

/**
 */
public class ConcatKeyDerivationFunctionTest extends TestCase
{
    public void testGetReps()
    {
        ConcatKeyDerivationFunction kdf = new ConcatKeyDerivationFunction("SHA-256");
        assertEquals(1, kdf.getReps(256));
        assertEquals(2, kdf.getReps(384));
        assertEquals(2, kdf.getReps(512));
        assertEquals(4, kdf.getReps(1024));
        assertEquals(5, kdf.getReps(1025));
    }

    public void testGetDatalenData()
    {
        String apu = "QWxpY2U";
        KdfUtil kdfUtil = new KdfUtil();
        byte[] apuDatalenData = kdfUtil.getDatalenDataFormat(apu);
        assertTrue(Arrays.equals(apuDatalenData, new byte[] {0, 0, 0, 5, 65, 108, 105, 99, 101}));

        String apv = "Qm9i";
        byte[] apvDatalenData = kdfUtil.getDatalenDataFormat(apv);
        assertTrue(Arrays.equals(apvDatalenData, new byte[] {0, 0, 0, 3, 'B', 'o', 'b'}));

        assertTrue(Arrays.equals(kdfUtil.prependDatalen(new byte[]{}), new byte[] {0, 0, 0, 0}));
        assertTrue(Arrays.equals(kdfUtil.prependDatalen(null), new byte[] {0, 0, 0, 0}));
    }
}
