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

import junit.framework.TestCase;
import org.jose4j.lang.ByteUtil;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 */
public class EcdsaUsingShaAlgorithmTest extends TestCase
{
    public void testEncodingDecoding() throws IOException
    {
        // not sure this is a *useful* test but what the heck...

        int[] rints = {14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88,
            7, 212, 2, 163, 178, 40, 3, 58, 249, 124, 126, 23, 129,
            154, 195, 22, 158, 166, 101};
        
        int[] sints =  {197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175,
            8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
            143, 63, 127, 138, 131, 163, 84, 213};

        byte[] rbytes = ByteUtil.convertUnsignedToSignedTwosComp(rints);
        byte[] sbytes = ByteUtil.convertUnsignedToSignedTwosComp(sints);

        ByteBuffer buffer = ByteBuffer.allocate(rbytes.length + sbytes.length);
        buffer.put(rbytes);
        buffer.put(sbytes);

        byte[] concatedBytes = buffer.array();
        byte[] derEncoded = EcdsaUsingShaAlgorithm.convertConcatenatedToDer(concatedBytes);
        assertFalse(Arrays.equals(concatedBytes, derEncoded));
        byte[] backToConcated = EcdsaUsingShaAlgorithm.convertDerToConcatenated(derEncoded);

        assertTrue(Arrays.equals(concatedBytes, backToConcated));
    }
}
