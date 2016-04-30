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

package org.jose4j.jwe;

import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.lang.JoseException;
import org.junit.Test;

/**
 *
 */
public class GeneralJweTest
{
    @Test(expected = NullPointerException.class)
    public void tryEncryptWithNullPlainText() throws JoseException
    {
        // I think it's probably correct to fail when encrypting and the plaintext is null
        // but should fail so in a way that's not confusing
        // it was, at one point, erroneously trying to decrypt inside of jwe.getCompactSerialization()
        // when it saw that the plantext bytes were null and then threw a misleading exception about
        // key validation
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
        jwe.setKeyIdHeaderValue("meh");
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        String compactSerialization = jwe.getCompactSerialization();
        System.out.println(compactSerialization);
    }
}
