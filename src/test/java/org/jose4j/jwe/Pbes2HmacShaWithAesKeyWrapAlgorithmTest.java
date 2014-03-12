/*
 * Copyright 2012-2014 Brian Campbell
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

import org.hamcrest.CoreMatchers;
import org.jose4j.keys.PbkdfKey;
import org.jose4j.lang.InvalidKeyException;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.*;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.*;

/**
 */
public class Pbes2HmacShaWithAesKeyWrapAlgorithmTest
{
    @Test
    public void roundTrips() throws Exception
    {
        String[] algs = new String[] {PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS256_A128KW};
        String[] encs = new String[] {AES_128_CBC_HMAC_SHA_256, AES_192_CBC_HMAC_SHA_384, AES_256_CBC_HMAC_SHA_512};

        String password = "password";
        String plaintext = "<insert some witty quote or remark here>";

        for (String alg : algs)
        {
            for (String enc : encs)
            {
                JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
                encryptingJwe.setAlgorithmHeaderValue(alg);
                encryptingJwe.setEncryptionMethodHeaderParameter(enc);
                encryptingJwe.setPayload(plaintext);
                encryptingJwe.setKey(new PbkdfKey(password));
                String compactSerialization = encryptingJwe.getCompactSerialization();

                JsonWebEncryption decryptingJwe = new JsonWebEncryption();
                decryptingJwe.setCompactSerialization(compactSerialization);
                decryptingJwe.setKey(new PbkdfKey(password));
                Assert.assertThat(plaintext, CoreMatchers.equalTo(decryptingJwe.getPayload()));
            }
        }
    }

    @Test (expected = InvalidKeyException.class)
    public void testNullKey() throws JoseException
    {
        JsonWebEncryption encryptingJwe  = new JsonWebEncryption();
        encryptingJwe.setAlgorithmHeaderValue(PBES2_HS256_A128KW);
        encryptingJwe.setEncryptionMethodHeaderParameter(AES_128_CBC_HMAC_SHA_256);
        encryptingJwe.setPayload("meh");

        encryptingJwe.getCompactSerialization();
    }



}
