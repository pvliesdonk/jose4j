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
package org.jose4j.jwe;

import org.jose4j.keys.AesKey;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class CritHeaderTest
{
    @Test
    public void testOnNewKey() throws Exception
    {
        final String headerName = "so.crit";
        final String otherHeaderName = "very.crit";

        final AesKey key = new AesKey(new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6});

        String jwecs =
            "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwic28uY3JpdCI6InllcCIsInZlcnkuY3JpdCI6ImVoIiwid2hhdCI6ImV2ZXIiLCJjcml0IjpbInNvLmNyaXQiXX0." +
            "kMto4viJ7TE6F9r6BuY7SJVRG04sJJlzCc0N2A-lZBxh5t3hGWTuJA." +
            "z3A09USgPKx-aR7hnVPzgA." +
            "edAUVi0TmIIPg84LyIbtXQ." +
            "waKimIov2wwgINaQ2gWPMA";

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(jwecs);
        jwe.setKey(key);

        org.jose4j.jws.CritHeaderTest.expectFail(jwe);

        jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(jwecs);
        jwe.setKey(key);
        jwe.setKnownCriticalHeaders(headerName, otherHeaderName);
        assertThat("Delayed in ORD", equalTo(jwe.getPayload()));
    }
}
