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

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.StringUtil;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 */
public class Aes256GcmContentEncryptionAlgorithmTest
{
    @Test
    public void testExampleEncryptFromJweAppendix1() throws Exception
    {
        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setDoReinitialize(false);
        jceProviderTestSupport.setEncryptionAlgsNeeded(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM);

        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                AesGcmContentEncryptionAlgorithm.Aes256Gcm aesGcmContentEncryptionAlg = new AesGcmContentEncryptionAlgorithm.Aes256Gcm();

                // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#appendix-A.1
                String plaintextText = "The true sign of intelligence is not knowledge but imagination.";
                byte[] plainText = StringUtil.getBytesUtf8(plaintextText);

                String encodedHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
                byte[] aad = StringUtil.getBytesAscii(encodedHeader);

                byte[] cek = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
                        212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
                        234, 64, 252});

                byte[] iv = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219});

                ContentEncryptionParts encryptionParts = aesGcmContentEncryptionAlg.encrypt(plainText, aad, cek, iv);

                Base64Url base64Url = new Base64Url();

                byte[] ciphertext = encryptionParts.getCiphertext();
                String encodedJweCiphertext = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A";
                assertThat(encodedJweCiphertext, equalTo(base64Url.base64UrlEncode(ciphertext)));

                byte[] authenticationTag = encryptionParts.getAuthenticationTag();
                String encodedAuthenticationTag = "XFBoMYUZodetZdvTiFvSkQ";
                assertThat(encodedAuthenticationTag, equalTo(base64Url.base64UrlEncode(authenticationTag)));

                ContentEncryptionParts parts = new ContentEncryptionParts(iv, ciphertext, authenticationTag);
                byte[] decrypted = aesGcmContentEncryptionAlg.decrypt(parts, aad, cek, null);
                assertArrayEquals(plainText, decrypted);
            }
        });

    }
}
