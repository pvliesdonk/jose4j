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
import org.jose4j.jwe.JsonWebEncryption;
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

    // http://tools.ietf.org/html/draft-ietf-jose-cookbook-01#section-4
    String jwePlaintext = "You can trust us to stick with you through thick and " +
            "thin–to the bitter end. And you can trust us to "+
            "keep any secret of yours–closer than you keep it " +
            "yourself. But you cannot trust us to let you face trouble " +
            "alone, and go off without a word. We are your friends, Frodo.";

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

    @Test
    public void encryptionRSAv1_5andAES_HMAC_SHA2_4_1() throws JoseException
    {
        String jwkJsonString =
                "   {\n" +
                        "     \"kty\": \"RSA\",\n" +
                        "     \"kid\": \"frodo.baggins@hobbiton.example\",\n" +
                        "     \"use\": \"enc\",\n" +
                        "     \"n\": \"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT\n" +
                        "         HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx\n" +
                        "         6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U\n" +
                        "         NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c\n" +
                        "         R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy\n" +
                        "         pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA\n" +
                        "         VotGlvMQ\",\n" +
                        "     \"e\": \"AQAB\",\n" +
                        "     \"d\": \"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy\n" +
                        "         bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO\n" +
                        "         5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6\n" +
                        "         Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP\n" +
                        "         1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN\n" +
                        "         miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v\n" +
                        "         pzj85bQQ\",\n" +
                        "     \"p\": \"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE\n" +
                        "         oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH\n" +
                        "         7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ\n" +
                        "         2VFmU\",\n" +
                        "     \"q\": \"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V\n" +
                        "         F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb\n" +
                        "         9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8\n" +
                        "         d6Et0\",\n" +
                        "     \"dp\": \"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH\n" +
                        "         QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV\n" +
                        "         RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf\n" +
                        "         lo0rYU\",\n" +
                        "     \"dq\": \"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb\n" +
                        "         pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A\n" +
                        "         CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14\n" +
                        "         TkXlHE\",\n" +
                        "     \"qi\": \"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ\n" +
                        "         lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7\n" +
                        "         Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx\n" +
                        "         2bQ_mM\"\n" +
                        "   }";

        String jweCompactSerialization =
                "eyJhbGciOiJSU0ExXzUiLCJraWQiOiJmcm9kby5iYWdnaW5zQGhvYmJpdG9uLm" +
                "V4YW1wbGUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0" +
                "." +
                "laLxI0j-nLH-_BgLOXMozKxmy9gffy2gTdvqzfTihJBuuzxg0V7yk1WClnQePF" +
                "vG2K-pvSlWc9BRIazDrn50RcRai__3TDON395H3c62tIouJJ4XaRvYHFjZTZ2G" +
                "Xfz8YAImcc91Tfk0WXC2F5Xbb71ClQ1DDH151tlpH77f2ff7xiSxh9oSewYrcG" +
                "TSLUeeCt36r1Kt3OSj7EyBQXoZlN7IxbyhMAfgIe7Mv1rOTOI5I8NQqeXXW8Vl" +
                "zNmoxaGMny3YnGir5Wf6Qt2nBq4qDaPdnaAuuGUGEecelIO1wx1BpyIfgvfjOh" +
                "MBs9M8XL223Fg47xlGsMXdfuY-4jaqVw" +
                "." +
                "bbd5sTkYwhAIqfHsx8DayA" +
                "." +
                "0fys_TY_na7f8dwSfXLiYdHaA2DxUjD67ieF7fcVbIR62JhJvGZ4_FNVSiGc_r" +
                "aa0HnLQ6s1P2sv3Xzl1p1l_o5wR_RsSzrS8Z-wnI3Jvo0mkpEEnlDmZvDu_k8O" +
                "WzJv7eZVEqiWKdyVzFhPpiyQU28GLOpRc2VbVbK4dQKPdNTjPPEmRqcaGeTWZV" +
                "yeSUvf5k59yJZxRuSvWFf6KrNtmRdZ8R4mDOjHSrM_s8uwIFcqt4r5GX8TKaI0" +
                "zT5CbL5Qlw3sRc7u_hg0yKVOiRytEAEs3vZkcfLkP6nbXdC_PkMdNS-ohP78T2" +
                "O6_7uInMGhFeX4ctHG7VelHGiT93JfWDEQi5_V9UN1rhXNrYu-0fVMkZAKX3VW" +
                "i7lzA6BP430m" +
                "." +
                "kvKuFBXHe5mQr4lqgobAUg";

        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jwkJsonString);

        // verify that we can decrypt it
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(jweCompactSerialization);
        jwe.setKey(jwk.getPrivateKey());
        assertThat(jwePlaintext, equalTo(jwe.getPlaintextString()));

    }
}
