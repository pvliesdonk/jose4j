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

package org.jose4j.cookbook;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 * http://tools.ietf.org/html/draft-ietf-jose-cookbook-01
 *
 * 3.1. RSA v1.5 Signature
 * ... PSS might drop in more easily than GCM w/ BC ... something to think about ...
 * 3.3. ECDSA Signature
 * 3.4. HMAC-SHA2 Integrity Protection
 * 3.5. Detached Signature
 *
 * 4.1. Key Encryption using RSA v1.5 and AES-HMAC-SHA2
 */
public class JoseCookbookTest
{
    // http://tools.ietf.org/html/draft-ietf-jose-cookbook-01#section-3
    String encodedJwsPayload =
            "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
            "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
            "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
            "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4";

    String jwsPayload = Base64Url.decodeToUtf8String(encodedJwsPayload);

    @Test
    public void rsa_v1_5Signature_3_1() throws JoseException
    {
        String jwkJson =
                "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"kid\": \"bilbo.baggins@hobbiton.example\",\n" +
                "  \"use\": \"sig\",\n" +
                "  \"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT\n" +
                "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV\n" +
                "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-\n" +
                "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde\n" +
                "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC\n" +
                "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g\n" +
                "HdrNP5zw\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e\n" +
                "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld\n" +
                "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b\n" +
                "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU\n" +
                "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj\n" +
                "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc\n" +
                "OpBrQzwQ\",\n" +
                "  \"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR\n" +
                "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG\n" +
                "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8\n" +
                "bUq0k\",\n" +
                "  \"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT\n" +
                "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an\n" +
                "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0\n" +
                "s7pFc\",\n" +
                "  \"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q\n" +
                "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn\n" +
                "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX\n" +
                "59ehik\",\n" +
                "  \"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr\n" +
                "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK\n" +
                "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK\n" +
                "T1cYF8\",\n" +
                "  \"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N\n" +
                "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh\n" +
                "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP\n" +
                "z8aaI4\"\n" +
                "}";

        String jwsCompactSerialization =
                "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" +
                "hhbXBsZSJ9" +
                "." +
                "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
                "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
                "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
                "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4" +
                "." +
                "MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmK" +
                "ZopdHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4J" +
                "IwmDLJK3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8w" +
                "W1Kt9eRo4QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluP" +
                "xUAhb6L2aXic1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_f" +
                "cIe8u9ipH84ogoree7vjbU5y18kDquDg";

        String alg = AlgorithmIdentifiers.RSA_USING_SHA256;

        // verify consuming the JWS
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        jws.setKey(jwk.getKey());
        assertThat(jws.verifySignature(), is(true));
        assertThat(jws.getPayload(), equalTo(jwsPayload));
        assertThat(jws.getKeyIdHeaderValue(), equalTo(jwk.getKeyId()));
        assertThat(alg, equalTo(jws.getAlgorithmHeaderValue()));

        // verify reproducing it (it's just luck that using the setters for the headers results in the exact same
        // JSON representation of the header)
        jws = new JsonWebSignature();
        jws.setPayload(jwsPayload);
        jws.setAlgorithmHeaderValue(alg);
        jws.setKeyIdHeaderValue(jwk.getKeyId());
        PublicJsonWebKey rsaJwk = (PublicJsonWebKey) jwk;
        jws.setKey(rsaJwk.getPrivateKey());
        String compactSerialization = jws.getCompactSerialization();
        assertThat(jwsCompactSerialization, equalTo(compactSerialization));
    }

    @Test
    public void ecdsaSignature_3_3() throws JoseException
    {
        String jwkJson = 
                "{\n" +
                "  \"kty\": \"EC\",\n" +
                "  \"kid\": \"bilbo.baggins@hobbiton.example\",\n" +
                "  \"use\": \"sig\",\n" +
                "  \"crv\": \"P-521\",\n" +
                "  \"x\": \"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9\n" +
                "      A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\",\n" +
                "  \"y\": \"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy\n" +
                "      SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\",\n" +
                "  \"d\": \"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb\n" +
                "      KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\"\n" +
                "}";


        String jwsCompactSerialization =
                "eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZX" +
                "hhbXBsZSJ9" +
                "." +
                "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
                "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
                "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
                "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4" +
                "." +
                "AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb" +
                "u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv" +
                "AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2";

        String alg = AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512;

        // verify consuming the JWS
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

        jws.setKey(jwk.getKey());
        assertThat(jws.getUnverifiedPayload(), equalTo(jwsPayload));

        assertThat(jws.verifySignature(), is(true));
        assertThat(jws.getPayload(), equalTo(jwsPayload));

        assertThat(jws.getKeyIdHeaderValue(), equalTo(jwk.getKeyId()));
        assertThat(alg, equalTo(jws.getAlgorithmHeaderValue()));

        // can't really verify reproducing ECDSA
    }

    @Test
    public void hmacSha2IntegrityProtection_3_4() throws JoseException
    {
        String jwkJson =
               "   {\n" +
               "     \"kty\": \"oct\",\n" +
               "     \"kid\": \"018c0ae5-4d9b-471b-bfd6-eef314bc7037\",\n" +
               "     \"use\": \"sig\",\n" +
               "     \"k\": \"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"\n" +
               "   }";

        String jwsCompactSerialization =
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW" +
                "VlZjMxNGJjNzAzNyJ9" +
                "." +
                "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
                "lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
                "b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
                "UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4" +
                "." +
                "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

        String alg = AlgorithmIdentifiers.HMAC_SHA256;

        // verify consuming the JWS
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwsCompactSerialization);
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        jws.setKey(jwk.getKey());
        assertThat(jws.verifySignature(), is(true));
        assertThat(jws.getPayload(), equalTo(jwsPayload));
        assertThat(jws.getKeyIdHeaderValue(), equalTo(jwk.getKeyId()));
        assertThat(alg, equalTo(jws.getAlgorithmHeaderValue()));

        // verify reproducing it
        jws = new JsonWebSignature();
        jws.setPayload(jwsPayload);
        jws.setAlgorithmHeaderValue(alg);
        jws.setKeyIdHeaderValue(jwk.getKeyId());
        jws.setKey(jwk.getKey());
        String compactSerialization = jws.getCompactSerialization();
        assertThat(jwsCompactSerialization, equalTo(compactSerialization));
    }

    @Test
    public void detached_3_5() throws JoseException
    {
        String jwkJsonString =
                "   {\n" +
                "     \"kty\": \"oct\",\n" +
                "     \"kid\": \"018c0ae5-4d9b-471b-bfd6-eef314bc7037\",\n" +
                "     \"use\": \"sig\",\n" +
                "     \"k\": \"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\"\n" +
                "   }";

        String detachedCs = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW" +
                "VlZjMxNGJjNzAzNyJ9" +
                "." +
                "." +
                "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(detachedCs);
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJsonString);
        jws.setKey(jwk.getKey());
        jws.setEncodedPayload(encodedJwsPayload);
        assertThat(jws.verifySignature(), is(true));
        assertThat(jws.getPayload(), equalTo(jwsPayload));

        // verify reproducing it (it's just luck that using the setters for the headers results in the exact same
        // JSON representation of the header)
        jws = new JsonWebSignature();
        jws.setPayload(jwsPayload);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setKeyIdHeaderValue(jwk.getKeyId());
        jws.setKey(jwk.getKey());
        // To create a detached signature, sign and then concatenate the encoded header, two dots "..", and the encoded signature
        jws.sign();
        String encodedHeader = jws.getHeaders().getEncodedHeader();
        String encodedSignature = jws.getEncodedSignature();
        String reproducedDetachedCs = encodedHeader + ".." + encodedSignature;
        assertThat(detachedCs, is(equalTo(reproducedDetachedCs)));
        assertThat(encodedJwsPayload, is(equalTo(jws.getEncodedPayload())));
    }


}
