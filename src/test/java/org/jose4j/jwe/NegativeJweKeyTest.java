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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleEcKeysFromJws;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.lang.JoseException;

import java.security.Key;

import static org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers.*;
import static org.jose4j.jwe.KeyManagementAlgorithmIdentifiers.*;

/**
 */
public class NegativeJweKeyTest extends TestCase
{
    Log log = LogFactory.getLog(this.getClass());

    public void testProduceA128KW() throws JoseException
    {
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(1));
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(5));
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(17));
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(24));
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, aesKey(32));
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PRIVATE_256);
        expectBadKeyFailOnProduce(A128KW, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PUBLIC_256);
    }

    public void testProduceA192KW() throws JoseException
    {
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(1));
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(5));
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(16));
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(23));
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, aesKey(32));
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PRIVATE_256);
        expectBadKeyFailOnProduce(A192KW, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PUBLIC_256);
    }

    public void testProduceA256KW() throws JoseException
    {
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(1));
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(5));
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(16));
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(24));
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(31));
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, aesKey(33));
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFailOnProduce(A256KW, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testProduceDirAndAes128() throws JoseException
    {
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(1));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(7));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(8));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(16));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(24));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(31));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(33));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(48));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, aesKey(64));
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFailOnProduce(DIRECT, AES_128_CBC_HMAC_SHA_256, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testProduceDirAndAes192() throws JoseException
    {
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(1));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(7));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(8));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(16));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(24));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(32));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(47));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(49));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, aesKey(64));
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFailOnProduce(DIRECT, AES_192_CBC_HMAC_SHA_384, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testProduceDirAndAes256() throws JoseException
    {
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(1));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(7));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(8));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(16));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(24));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(32));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(48));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(63));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, aesKey(65));
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey());
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleRsaJwksFromJwe.APPENDIX_A_2.getPublicKey());
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PRIVATE_521);
        expectBadKeyFailOnProduce(DIRECT, AES_256_CBC_HMAC_SHA_512, ExampleEcKeysFromJws.PUBLIC_521);
    }

    public void testConsumeKeySizeMismatch1() throws JoseException
    {
        String cs = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                    "piLjD7hmzHarXM2IjTo8OjXj419Ah1MmF-xCQI3NUjResRSzodogQw." +
                    "Hk5d-oTNmRz14KE97aV-Fg.xQbNIstt09YIBUmM6YZObw.HT-xvG9FLP6MxwORQLgxxg";
        expectBadKeyFailOnConsume(cs, aesKey(24));
    }

    public void testConsumeKeySizeMismatch2() throws JoseException
    {
        String cs = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                    "mBJfKY7jaysbRL-KPckey-8n20rnGv7TWN2xxWg9bwcsod-aWQXnig." +
                    "I4Rm3UTzpohTSBFxXCz3rA.-1CpOM9RVaSYsVbw6Okhdg.UnvHRrgyOtndiYGOtv_m-Q\n";
        expectBadKeyFailOnConsume(cs, aesKey(32));
    }

    public void testConsumeKeySizeMismatch3() throws JoseException
    {
        String cs = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0." +
                    "V6ia6W1lFpeeJErBy9G7BdUXiAdh__5FFFM8RNu_bqD15Yn2JqF7YlhuTwbmsxjpxAFl4u-gEC4." +
                    "Rob8WxK9RFfz4HlnPDD6AA.QFezmkSMy0tWf3-ck_T8og.RwrijoudPY5JJbiVCiYvwhEsptZyQjTk";
        expectBadKeyFailOnConsume(cs, aesKey(16));
    }

    public void testConsumeKeySizeMismatch4() throws JoseException
    {
        String cs = " eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0." +
                "zxDbVmrW2AlF1R3twiqrXD16dqe5tzcgA-1-5-Kltdk1trcxxs3FWfS5KYAe7E-n_Ibdrtx4Jyg." +
                "_nVmQa1RPbStDTJyD-6vmg.fMFd4wNNmxJzwPTxxIas6Q.0ZAuXetx6u-h5UYQdEED8yvRtGtRVap4";
        expectBadKeyFailOnConsume(cs, aesKey(32));
    }

    public void testConsumeKeySizeMismatch5() throws JoseException
    {
        String cs = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0." +
                "CUf42Kh7kiG8EsOu9VUKKT9wA3gsaQxm7SmH6Au-Bpr9qQZyw6cRN-EU2XNBCLK2grnGecZofaapAcsEXazseP_hOlsD85fw." +
                "9aTasBSY_Ed_1Gyaf9T1yw.sKtEMcaijs6kzLFuoUAFNg.DufxVwkEcAyfGwZcrP3FJ6H1AsH7Vpdiu-3t9-3y_gs";
        expectBadKeyFailOnConsume(cs, aesKey(16));
    }

    public void testConsumeKeySizeMismatch6() throws JoseException
    {
        String cs = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0." +
                "q95oRWEcqb0a31GpOBfUIj9uZHMP51CmfqGcLw1d1rywxPjFKW0uLpDRRFbXz--n3KL9BBNXZCJQ8a1niNbz85B9d3YBzvt1." +
                "tAQVsLHcOaZ5-SKzOEFXsg.qSA7hqdSlb6l10R2I_m8eA.4KEjAYDhTLUqRNrgvMRNKWfcdjhnJTw5iGlHozF99i8";
        expectBadKeyFailOnConsume(cs, aesKey(24));
    }

    public void testConsumeKeySizeMismatch7() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.." +
                "DhBs7zz8d4DmHeF_OAHxnA.QcLu7u_0Vl6EaOg0UB5YHA.v-0AEf-NgmyqfPLrnyNEyg";
        expectBadKeyFailOnConsume(cs, aesKey(33));
    }

    public void testConsumeKeySizeMismatch8() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.." +
                "zvuhYR4uc2eiKziPep3tNQ.ufJ6A7LHTyEspKaV582TTg.Tzlj1Wi7Cdkx-k5ColVgEQ";
        expectBadKeyFailOnConsume(cs, aesKey(48));
    }

    public void testConsumeKeySizeMismatch9() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.." +
                "nQWLu7PB-d4ZHazU42ljiQ.FwvbiGVFCZE2wy4dS7sLxg.6jP9_W8L4tBEfHAu18Hj_A";
        expectBadKeyFailOnConsume(cs, aesKey(64));
    }

    public void testConsumeKeySizeMismatch10() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.." +
                "D9P2JTGqnAP6W6xN3n-twQ.3wBV0wv_bLTmRVnvX_YnLQ.pgkcaNh7ZjdAcBO1yKtObDQ3HU0rXnzo";
        expectBadKeyFailOnConsume(cs, aesKey(32));
    }

    public void testConsumeKeySizeMismatch11() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.." +
                "btkRpNzeamtVj26p4Y3rNA.VHiVCfawJY_2fIMLHlxPFA.UhXTQ1vxaIFiRN_8pGgjdGkxoKUOy03F";
        expectBadKeyFailOnConsume(cs, aesKey(49));
    }

    public void testConsumeKeySizeMismatch12() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.." +
                "dtaa23ilH0MAv-DRI_CZdQ.NycLiCtG2lSBoT5yxJLqag.CMR2mhqz8v1dQfCvLduWhC1aAx5QhXY7";
        expectBadKeyFailOnConsume(cs, aesKey(64));
    }

    public void testConsumeKeySizeMismatch13() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.." +
                "bvmPzabWZFdbiDrJLDoQVw.i7aWtdTVPhVgVDP0lx8TnA.djK6f7tQ44T8aBAfblXu8qA4j9KHMjomy_Ho0sb4S1g";
        expectBadKeyFailOnConsume(cs, aesKey(64));
    }

    public void testConsumeKeySizeMismatch14() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.." +
                "HHgNXhSr5vPQoVyV5rkGzg.grgmRjvvFJ5nNioVRcbJTg.AE7e8fHqFOI91Y52W9kpUNqr1jKGq3DoSVCjyjq3mVo";
        expectBadKeyFailOnConsume(cs, aesKey(48));
    }

    public void testConsumeKeySizeMismatch15() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.." +
                "VC5VhumdESJ0-4I0c8bW2A.2tFEdedX4JdxiXf3RGL2eA.KMIsWU0rWGdO4YAvp-3TX1Q-aMAQqXsDwXBQKu-BJgo";
        expectBadKeyFailOnConsume(cs, aesKey(65));
    }

    public void testUnexpectedEncryptedKey() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +   // dir
                "F6EJj1gzyuttczguncypZOk31wMnVajr1IpS-ZnXMeW72QqurUKlBA." + // should not have an encrypted key part
                "SzF11wzK9JfHTsfPbPgixw." +
                "7wGWU2oy1fPXf_HoGGfuqCwMLwkvOOjgFF4YA_iwzUUqkwLX5tEOUq76Qgk7LSg6cgc8VK-4ZEqaaFLwwnQ9gw." +
                "3C7wAt7-OSgD6QMkccW48A";

        expectBadKeyFailOnConsume(cs, aesKey(32));
    }

    private void expectBadKeyFailOnConsume(String cs, Key key) throws JoseException
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(cs);
        jwe.setKey(key);

        try
        {
            String plaintextString = jwe.getPlaintextString();
            fail("plaintextString w/ "+jwe.getHeaders().getFullHeaderAsJsonString() +
                    " should have failed due to bad key ("+key+") but gave " + plaintextString);
        }
        catch (JoseException e)
        {
            log.debug("Expected exception due to invalid key: " + e);
        }
    }

    private void expectBadKeyFailOnProduce(String alg, String enc, Key key)
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPlaintext("PLAIN OLD TEXT");
        jwe.setAlgorithmHeaderValue(alg);
        jwe.setEncryptionMethodHeaderParameter(enc);
        jwe.setKey(key);

        try
        {
            String cs = jwe.getCompactSerialization();
            fail("getCompactSerialization w/ "+alg +"/"+enc+" should have failed due to bad key ("+key+") but gave " + cs);
        }
        catch (JoseException e)
        {
            log.debug("Expected exception due to invalid key: " + e);
        }

    }

    private AesKey aesKey(int byteLength)
    {
        return new AesKey(new byte[byteLength]);
    }
}
