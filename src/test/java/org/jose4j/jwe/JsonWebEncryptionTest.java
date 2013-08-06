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

package org.jose4j.jwe;

import junit.framework.TestCase;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 */
public class JsonWebEncryptionTest extends TestCase
{
    public void testJweExampleA3() throws JoseException
    {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#appendix-A.3
        String jweCsFromAppdxA3 = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
                "AxY8DCtDaGlsbGljb3RoZQ." +
                "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
                "U0m_YmjN04DJvceFICbCVQ";

        JsonWebEncryption jwe = new JsonWebEncryption();
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("\n" +
                "{\"kty\":\"oct\",\n" +
                " \"k\":\"GawgguFyGrWKav7AX4VKUg\"\n" +
                "}");

        jwe.setCompactSerialization(jweCsFromAppdxA3);
        jwe.setKey(new AesKey(jsonWebKey.getKey().getEncoded()));

        String plaintextString = jwe.getPlaintextString();

        assertEquals("Live long and prosper.", plaintextString);

    }

    public void testJweExampleA2() throws JoseException
    {
        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#appendix-A.2
        String jweCsFromAppendixA2 = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm" +
                "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc" +
                "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF" +
                "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8" +
                "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv" +
                "-B3oWh2TbqmScqXMR4gp_A." +
                "AxY8DCtDaGlsbGljb3RoZQ." +
                "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
                "9hH0vgRfYgPnAHOd8stkvw";

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        jwe.setCompactSerialization(jweCsFromAppendixA2);
        String plaintextString = jwe.getPlaintextString();
        assertEquals("Live long and prosper.", plaintextString);
    }

    public void testHappyRoundTripRsa1_5AndAesCbc128() throws JoseException
    {
        JsonWebEncryption jweForEncrypt = new JsonWebEncryption();
        String plaintext = "Some text that's on double secret probation";
        jweForEncrypt.setPlaintext(plaintext);
        jweForEncrypt.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
        jweForEncrypt.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jweForEncrypt.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());

        String compactSerialization = jweForEncrypt.getCompactSerialization();

        JsonWebEncryption jweForDecrypt = new JsonWebEncryption();
        jweForDecrypt.setCompactSerialization(compactSerialization);
        jweForDecrypt.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());

        assertEquals(plaintext, jweForDecrypt.getPlaintextString());
    }


    public void testHappyRoundTripDirectAndAesCbc128() throws JoseException
    {
        JsonWebEncryption jweForEncrypt = new JsonWebEncryption();
        String plaintext = "Some sensitive info";
        jweForEncrypt.setPlaintext(plaintext);
        jweForEncrypt.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jweForEncrypt.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        ContentEncryptionAlgorithm contentEncryptionAlgorithm = jweForEncrypt.getContentEncryptionAlgorithm();
        ContentEncryptionKeyDescriptor cekDesc = contentEncryptionAlgorithm.getContentEncryptionKeyDescriptor();
        byte[] cekBytes = ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength() * 2);
        Key key = new SecretKeySpec(cekBytes, cekDesc.getContentEncryptionKeyAlgorithm());
        jweForEncrypt.setKey(key);

        String compactSerialization = jweForEncrypt.getCompactSerialization();

        JsonWebEncryption jweForDecrypt = new JsonWebEncryption();
        jweForDecrypt.setCompactSerialization(compactSerialization);
        jweForDecrypt.setKey(key);

        assertEquals(plaintext, jweForDecrypt.getPlaintextString());
    }

}
