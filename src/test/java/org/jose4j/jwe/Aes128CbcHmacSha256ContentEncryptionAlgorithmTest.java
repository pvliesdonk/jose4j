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

import junit.framework.TestCase;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContextTest;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

/**
 */
public class Aes128CbcHmacSha256ContentEncryptionAlgorithmTest extends TestCase
{
    public void testExampleEncryptFromJweAppendix2() throws JoseException
    {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-13#appendix-A.2
        String plainTextText = "Live long and prosper.";
        byte[] plainText = StringUtil.getBytesUtf8(plainTextText);

        String encodedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0" +
                "JDLUhTMjU2In0";
        Base64Url base64url = new Base64Url();
        Headers headers = new Headers();
        headers.setFullHeaderAsJsonString(base64url.base64UrlDecodeToUtf8String(encodedHeader));

        byte[] aad = StringUtil.getBytesAscii(encodedHeader);

        int[] ints = {4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207};
        byte[] contentEncryptionKeyBytes = ByteUtil.convertUnsignedToSignedTwosComp(ints);

        byte[] iv = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101});

        AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256 jweContentEncryptionAlg = new AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256();
        ContentEncryptionParts contentEncryptionParts = jweContentEncryptionAlg.encrypt(plainText, aad, contentEncryptionKeyBytes, iv, headers, ProviderContextTest.EMPTY_CONTEXT);

        Base64Url base64Url = new Base64Url();

        byte[] ciphertext = contentEncryptionParts.getCiphertext();
        String encodedJweCiphertext = "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY";
        assertEquals(encodedJweCiphertext, base64Url.base64UrlEncode(ciphertext));

        byte[] authenticationTag = contentEncryptionParts.getAuthenticationTag();
        String encodedAuthenticationTag = "9hH0vgRfYgPnAHOd8stkvw";
        assertEquals(encodedAuthenticationTag, base64Url.base64UrlEncode(authenticationTag));
    }

    public void testExampleDecryptFromJweAppendix2() throws JoseException
    {
        int[] ints = {4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207};
        byte[] contentEncryptionKeyBytes = ByteUtil.convertUnsignedToSignedTwosComp(ints);

        Base64Url b = new Base64Url();

        String encodedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        Headers headers = new Headers();
        headers.setFullHeaderAsJsonString(Base64Url.decodeToUtf8String(encodedHeader));

        byte[] header = StringUtil.getBytesUtf8(encodedHeader);
        byte[] iv = b.base64UrlDecode("AxY8DCtDaGlsbGljb3RoZQ");
        byte[] ciphertext = b.base64UrlDecode("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY");
        byte[] tag = b.base64UrlDecode("9hH0vgRfYgPnAHOd8stkvw");

        AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256 jweContentEncryptionAlg = new AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256();
        ContentEncryptionParts encryptionParts = new ContentEncryptionParts(iv, ciphertext, tag);
        byte[] plaintextBytes = jweContentEncryptionAlg.decrypt(encryptionParts, header, contentEncryptionKeyBytes, headers, ProviderContextTest.EMPTY_CONTEXT);

        assertEquals("Live long and prosper.", StringUtil.newStringUtf8(plaintextBytes));
    }

    public void testRoundTrip() throws JoseException
    {
        String text = "I'm writing this test on a flight to Zurich";
        String encodedHeader = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0";
        Headers headers = new Headers();
        headers.setFullHeaderAsJsonString(Base64Url.decodeToUtf8String(encodedHeader));
        byte[] aad = StringUtil.getBytesUtf8(encodedHeader);
        byte[] plaintext = StringUtil.getBytesUtf8(text);
        AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256 contentEncryptionAlg = new AesCbcHmacSha2ContentEncryptionAlgorithm.Aes128CbcHmacSha256();
        ContentEncryptionKeyDescriptor cekDesc = contentEncryptionAlg.getContentEncryptionKeyDescriptor();
        byte[] cek = ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength());
        ContentEncryptionParts encryptionParts = contentEncryptionAlg.encrypt(plaintext, aad, cek, headers, null, ProviderContextTest.EMPTY_CONTEXT);

        byte[] decrypt = contentEncryptionAlg.decrypt(encryptionParts, aad, cek, null, ProviderContextTest.EMPTY_CONTEXT);
        assertEquals(text, StringUtil.newStringUtf8(decrypt));
    }


}
