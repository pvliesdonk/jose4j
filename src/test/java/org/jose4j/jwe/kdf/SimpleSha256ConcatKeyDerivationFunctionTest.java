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
public class SimpleSha256ConcatKeyDerivationFunctionTest extends TestCase
{
    public void testGetReps()
    {
        ShaConcatKeyDerivationFunction kdf = new Sha256ConcatKeyDerivationFunction();
        assertEquals(1, kdf.getReps(256));
        assertEquals(2, kdf.getReps(384));
        assertEquals(2, kdf.getReps(512));
        assertEquals(4, kdf.getReps(1024));
        assertEquals(5, kdf.getReps(1025));
    }

    public void testSizeEtc256()
    {
        testKdfSizeAndOtherStuff(256);
    }

    public void testSizeEtc384()
    {
        testKdfSizeAndOtherStuff(384);
    }

    public void testSizeEtc512()
    {
        testKdfSizeAndOtherStuff(512);
    }

    public void testGetDatalenData()
    {
        String apu = "QWxpY2U";
        ShaConcatKeyDerivationFunction kdf = new Sha256ConcatKeyDerivationFunction();
        byte[] apuDatalenData = kdf.getDatalenDataFormat(apu);
        assertTrue(Arrays.equals(apuDatalenData, new byte[] {0, 0, 0, 5, 65, 108, 105, 99, 101}));

        String apv = "Qm9i";
        byte[] apvDatalenData = kdf.getDatalenDataFormat(apv);
        assertTrue(Arrays.equals(apvDatalenData, new byte[] {0, 0, 0, 3, 'B', 'o', 'b'}));

        assertTrue(Arrays.equals(kdf.prependDatalen(new byte[]{}), new byte[] {0, 0, 0, 0}));
        assertTrue(Arrays.equals(kdf.prependDatalen(null), new byte[] {0, 0, 0, 0}));
    }

    public void testKdfSizeAndOtherStuff(int keydatalen)
    {
        ShaConcatKeyDerivationFunction kdf1 = new Sha256ConcatKeyDerivationFunction();
        byte[] secret = {1, 62, 3, 4, 9, 83, 123, 12, 111, 1, 1, 0, -1, 8, 7 , 12, 45, 118, 99, 9};
    }
}
