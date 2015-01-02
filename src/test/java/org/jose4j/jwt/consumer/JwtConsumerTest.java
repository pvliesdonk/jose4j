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

package org.jose4j.jwt.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class JwtConsumerTest
{
    //TODO more tests - nested and non nested. Unexpected exceptions. Bad AEAD. Wrong keys. Null keys.
    Log log = LogFactory.getLog(this.getClass());

    @Test
    public void jwt61ExampleUnsecuredJwt() throws InvalidJwtException, MalformedClaimException
    {
        // an Example Unsecured JWT from https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-6.1
        String jwt =
                "eyJhbGciOiJub25lIn0" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                ".";

        // works w/ 'NO_CONSTRAINTS' and setDisableRequireSignature() and null key
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .setDisableRequireSignature()
                .build();
        JwtClaimsSet jcs = consumer.processToClaims(jwt);
        Assert.assertThat("joe", equalTo(jcs.getIssuer()));
        Assert.assertThat(NumericDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));


        // fails w/ default constraints
        consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .build();
         expectProcessingFailure(jwt, consumer);

        // fails w/ explicit constraints
        consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLACKLIST, AlgorithmIdentifiers.NONE, AlgorithmIdentifiers.RSA_PSS_USING_SHA256))
                .build();
        expectProcessingFailure(jwt, consumer);


        // fail w/ 'NO_CONSTRAINTS' but a key provided
        consumer = new JwtConsumerBuilder()
                .setVerificationKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getKey())
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .build();
        expectProcessingFailure(jwt, consumer);

        // fail w/ 'NO_CONSTRAINTS' and no key but sig required (by default)
        consumer = new JwtConsumerBuilder()
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .build();
        expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void jwtA1ExampleEncryptedJWT() throws InvalidJwtException, MalformedClaimException
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.1
        String jwt = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
                "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM" +
                "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG" +
                "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima" +
                "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52" +
                "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" +
                "1rZgN5TiysnmzTROF869lQ." +
                "AxY8DCtDaGlsbGljb3RoZQ." +
                "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM" +
                "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." +
                "fiK51VwhsxJ-siBMR-YFiA";

        JwtConsumer c = new JwtConsumerBuilder()
                .setExpectedIssuer("joe")
                .setEvaluationTime(NumericDate.fromSeconds(1300819300))
                .setDecryptionKey(ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey())
                .setDisableRequireSignature()
                .build();

        JwtContext context = c.process(jwt);
        JwtClaimsSet jcs = context.getJwtClaimsSet();
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));
        String expectedPayload = "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
        assertThat(jcs.getRawJson(), equalTo(expectedPayload));
        assertThat(1, equalTo(context.getJoseObjects().size()));
    }

    @Test
    public void jwtA2ExampleNestedJWT() throws InvalidJwtException, MalformedClaimException
    {
       // an Example Nested JWT from https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#appendix-A.2
       String jwt = 
               "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" +
               "In0." +
               "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M" +
               "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE" +
               "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh" +
               "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D" +
               "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" +
               "JGTO_z3Wfo5zsqwkxruxwA." +
               "UmVkbW9uZCBXQSA5ODA1Mg." +
               "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB" +
               "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT" +
               "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10" +
               "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY" +
               "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr" +
               "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2" +
               "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE" +
               "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U" +
               "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd" +
               "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." +
               "AVO9iT5AV4CzvDJCdhSFlQ";

        PrivateKey decryptionKey = ExampleRsaJwksFromJwe.APPENDIX_A_2.getPrivateKey();
        RSAPublicKey verificationKey = ExampleRsaKeyFromJws.PUBLIC_KEY;
        JwtConsumerBuilder builder = new JwtConsumerBuilder()
                .setDecryptionKey(decryptionKey)
                .setEnableRequireEncryption()
                .setVerificationKey(verificationKey)
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819380))
                .setAllowedClockSkewInSeconds(30)
                .setExpectedIssuer("joe");
        JwtConsumer jwtConsumer = builder.build();

        JwtContext jwtInfo = jwtConsumer.process(jwt);

        Assert.assertThat(2, equalTo(jwtInfo.getJoseObjects().size()));
        Assert.assertTrue(jwtInfo.getJoseObjects().get(0) instanceof JsonWebSignature);
        Assert.assertTrue(jwtInfo.getJoseObjects().get(1) instanceof JsonWebEncryption);

        JwtClaimsSet jcs = jwtInfo.getJwtClaimsSet();

        Assert.assertThat("joe", equalTo(jcs.getIssuer()));
        Assert.assertThat(NumericDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));
    }

    @Test
    public void jwtSec31ExampleJWT() throws Exception
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3.1
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(JsonWebKey.Factory.newJwk(jwk).getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        Assert.assertTrue(context.getJwtClaimsSet().getClaimValue("http://example.com/is_root", Boolean.class));
        assertThat(1, equalTo(context.getJoseObjects().size()));

        // require encryption and it will fail
        consumer = new JwtConsumerBuilder()
                .setEnableRequireEncryption()
                .setVerificationKey(JsonWebKey.Factory.newJwk(jwk).getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1300819372))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        expectProcessingFailure(jwt, consumer);
    }

    @Test (expected = InvalidJwtSignatureException.class)
    public void jwtBadSig() throws Exception
    {
        String jwt = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                "eyJpc3MiOiJqb2UiLAogImV4cCI6MTkwMDgxOTM4MCwKICJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZX0." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String jwk = "{\"kty\":\"oct\",\"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"}";

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(JsonWebKey.Factory.newJwk(jwk).getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1900000380))
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .build();
        consumer.process(jwt);
    }

    @Test
    public void algConstraints() throws Exception
    {
        String jwt =
                "eyJ6aXAiOiJERUYiLCJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldUIn0" +
                ".DDyrirrztC88OaDtTkkNgNIyZqQd4gjWrab9KkiBnyOULjWZWt-IAg" +
                ".Obun_t7l3FYqNUqyW46syg" +
                ".ChlzoLTN1ovJP9PLHlirc-_yvP4ya_5gdhDSKiZnifS9MjCbeMYebkOCxSHexs09PBbPv30JwtIyM7caqkSNggA8HT_ub1moMpx0uOFhTE9dpdY4Wb4Ym6mqtIQhdwLymDVCI6vRn-NH88vdLluGSYYLhelgcL05qeWJQKzV3mxopgM-Q7N7LycXrodqTdvM" +
                ".ay9pwehz96tJgRKvSwASDg";
        JsonWebKey macKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"j-QRollN4PYjebWYcTl32YOGWfdpXi_YYHu03Ifp8K4\"}");
        JsonWebKey wrapKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"sUMs42PKNsKn9jeGJ2szKA\"}");

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtClaimsSet jwtClaimsSet = consumer.processToClaims(jwt);
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.HMAC_SHA256))
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, KeyManagementAlgorithmIdentifiers.A128KW))
                .setJweContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256))
                .build();
        jwtClaimsSet = consumer.processToClaims(jwt);
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLACKLIST, AlgorithmIdentifiers.HMAC_SHA256))
                .build();
        expectProcessingFailure(jwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJweAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLACKLIST, KeyManagementAlgorithmIdentifiers.A128KW))
                .build();
        expectProcessingFailure(jwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(wrapKey.getKey())
                .setVerificationKey(macKey.getKey())
                .setEvaluationTime(NumericDate.fromSeconds(1419982016))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .setJweContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLACKLIST, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256))
                .build();
        expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void customValidatorTest() throws Exception
    {
        // {"iss":"same","aud":"same","exp":1420046060}
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiYXVkIjoic2FtZSIsImV4cCI6MTQyMDA0NjA2MH0.O1w_nkfQMZvEEvJ0Pach0gPmJUMW8o4aFlA1f2c8m-I";
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"IWlxz1h43wKzyigIXNn-dTRBu89M9L8wmJK4zZmUXrQ\"}");
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046040))
                .setExpectedAudience("same", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .build();

        JwtContext process = consumer.process(jwt);
        Assert.assertThat(1, equalTo(process.getJoseObjects().size()));

        consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046040))
                .setExpectedAudience("same", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .registerValidator(new Validator()
                {
                    @Override
                    public String validate(JwtContext jwtContext) throws MalformedClaimException
                    {
                        JwtClaimsSet jcs = jwtContext.getJwtClaimsSet();
                        String audience = jcs.getAudience().iterator().next();
                        String issuer = jcs.getIssuer();

                        if (issuer.equals(audience))
                        {
                            return "You can go blind issuing tokens to yourself...";
                        }

                        return null;
                    }
                })
                .build();

        expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void wrappedNpeFromCustomValidatorTest() throws Exception
    {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzYW1lIiwiZXhwIjoxNDIwMDQ2ODE0fQ.LUViXhiMJRZa5veg6ayZCDQaIc0GfVDJDx-878WbFzg";
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"Ek1bHgP9uYyEtB5-V6oAzT_wB4mUnvCpirPqO4MyFwE\"}");
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046767))
                .setExpectedAudience(false, "other", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .build();

        JwtContext process = consumer.process(jwt);
        Assert.assertThat(1, equalTo(process.getJoseObjects().size()));

        consumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1420046768))
                .setExpectedAudience(false, "other", "different")
                .setExpectedIssuer("same")
                .setRequireExpirationTime()
                .setVerificationKey(jsonWebKey.getKey())
                .registerValidator(new Validator()
                {
                    @Override
                    public String validate(JwtContext jwtContext) throws MalformedClaimException
                    {
                        try
                        {
                            JwtClaimsSet jcs = jwtContext.getJwtClaimsSet();
                            List<String> audience = jcs.getAudience();
                            Iterator<String> iterator = audience.iterator();  // this will NPE
                            iterator.next();

                            return null;
                        }
                        catch (Exception e)
                        {
                            throw new RuntimeException("Something bad happened.", e);
                        }
                    }
                })
                .build();

        expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void missingCtyInNested() throws Exception
    {
        // Nested jwt without "cty":"JWT" -> expect failure here as the cty is a MUST for nesting. But, in the future, we may consider making an effort to deal
        // with the content even when cty isn't specified

        String jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsIngiOiIwRGk0VTBZQ0R2NHAtS2hETUZwUThvY0FsZzA2SEwzSHR6UldRbzlDLWV3IiwieSI6IjBfVFJjR1Y3Qy05d0xseFJZSExJOFlKTXlET2hWNW5YeHVPMGdRVmVxd0EiLCJjcnYiOiJQLTI1NiJ9fQ..xw5H8Kztd_sqzbXjt4GKUg.YNa163HLj7MwlvjzGihbOHnJ2PC3NOTnnvVOanuk1O9XFJ97pbbHHQzEeEwG6jfvDgdmlrLjcIJkSu1U8qRby7Xr4gzP6CkaDPbKwvLveETZSNdmZh37XKfnQ4LvKgiko6OQzyLYG1gc97kUOeikXTYVaYaeV1838Bi4q3DsIG-j4ZESg0-ePQesw56A80AEE3j6wXwZ4vqugPP9_ogZzkPFcHf1lt3-A4amNMjDbV8.u-JJCoakXI55BG2rz_kBlg";
        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"loF6m9WAW_GKrhoh48ctg_d78fbIsmUb02XDOwJj59c\",\"y\":\"kDCHDkCbWjeX8DjD9feQKcndJyerdsLJ4VZ5YSTWCoU\",\"crv\":\"P-256\",\"d\":\"6D1C9gJsT9KXNtTNyqgpdyQuIrK-qzo0_QJOVe9DqJg\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"PNbMydlpYRBFTYn_XDFvvRAFqE4e0EJmK6-zULTVERs\",\"y\":\"dyO9wGVgKS3gtP5bx0PE8__MOV_HLSpiwK-mP1RGZgk\",\"crv\":\"P-256\",\"d\":\"FIs8wVojHBdl7vkiZVnLBPw5S9lbn4JF2WWY1OTupic\"}");

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        expectProcessingFailure(jwt, consumer);
    }

    @Test
    public void ctyValueVariationsInNested() throws Exception
    {
        // Nested jwt with variations on "cty":"JWT" like jwt, application/jwt, application/JWT ...

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");

        String jwt;
        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6ImFwcGxpY2F0aW9uL2p3dCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJCOUhPbG82UV9LV0NiQjZLbk1RMDFfaHcyRXdaQWNEMmNucEdYYVl5WFBBIiwieSI6InJYS2s3VzM4UXhVOHl4YWZZc3NsUjFWU2JLbDI5T0FNSWxROFBCWXVZcUEiLCJjcnYiOiJQLTI1NiJ9fQ..LcIG9_bnPb43aaps32H6yQ.rsV7ItJWWfNafDJmeLHluKhiwmsU0Mlwut2jwD6y96KpjD-hz_5zBxpXtj6mk8yGZwg2L26XLo8npt_82bhKnMYqlKSRM-3ge2Deg5WPmBCx6Fj0NyCMnoR8oJTn-oxh0OHZICK_85Xz3GptopeA3Hj8ESdsJEI6D4WbXQ7HfGeg8ID9uvTaL8NGOHT4BGY0bB-6nl3qNIY5ULpg-a4a1ou5k9HnM6SRSpVRwpBBUsk.1vqvwv9XAzsQfvragyMXZQ";
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        JwtClaimsSet jwtClaimsSet = context.getJwtClaimsSet();
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));

        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6ImFwcGxpY2F0aW9uL0pXVCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJxelBlRUl0ZXJmQ0dhTFBpbDU3UmRudERHQVdwdVlBRGtVLUJubkkyTXowIiwieSI6ImNmWUxlc1dneGlfVndCdzdvSzNPT3dabGNrbVRCVmMzcEdnMTNRZ3V5WjQiLCJjcnYiOiJQLTI1NiJ9fQ..ftNMf4CqUSCq8p3L1Y7K1A.Z9K1YIJmSY9du5LUuSs0szCj1PUzq0ZnsEppT8yVPdGVDkDi0elEcsM8dCq8CvYrXG8OFuyp0s8dd2u_fIw4RjMc-aVMBT4ikWDmqb4CA17nC2Hxm6dZFPy3Xx3GnqjiGUIB2JiMOxj6mBZtTSvkKAUvs3Rh4G-87v2hJFpqdLSySqd-rQXL7Dhqxl0Cbu9nZFcYEIk58lpC0H2TN9aP5GtuQYa3BlNuEoEDzIcLhc4.N6VFQ0_UgNqyBsPLyE6MQQ";
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219095))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        context = consumer.process(jwt);
        jwtClaimsSet = context.getJwtClaimsSet();
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));

        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6Imp3dCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJoTm5zTlRXZWN3TEVRUGVRMlFjZ05WSDJLX0dzTkFUZXNVaENhY2x2OVAwIiwieSI6ImI2V1lSR1V5Z1NBUGo5a0lFYktYTm5ZaDhEbmNrRXB2NDFYbUVnanA4VE0iLCJjcnYiOiJQLTI1NiJ9fQ..VGTURmPYERdJ7q9_5wlENA.91m_JN65XNlp9WsFHaHihhGB7soKNUdeBNpmODVcIiinhPClH00-GTMwfT08VmXEU2djW3Aw_eBAoU7rI_M0ovYbbmAy7UnVRUyCTbkGsQpv7OxYIznemMVMraFuHNmTAF_MU7oM4gPkqKzwuBa0uwd4JhN00bq-jEcLifMPgMvyGvfJ19SXAyrIVA4Otjuii347V5u1GwlB5VBqMiqtBnbMMzR1Fe3X-4-sEgT9BrM.4T3uLGa4Bm5_r-ZNKPzEWg";
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219099))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        context = consumer.process(jwt);
        jwtClaimsSet = context.getJwtClaimsSet();
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));

        jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImN0eSI6ImpXdCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJmYTlJVEh6cEROSG1uV2NDSDVvWGtFYjJ1SncwTXNOU2stQjdFb091WUEwIiwieSI6IkZ1U0RaVXdmb1EtQXB6dEFQRUc1dk40QmZRR2sxWnRMT0FzM1o0a19obmciLCJjcnYiOiJQLTI1NiJ9fQ..FmuORwLWIoNBbRh0XcBzJQ.pSr58DMuRstF3A6xj24yM4KvNgWxtb_QDKuldesTCD-R00BNFwIVx4F51VL5DwR54ITgBZBKdAT4pN6eM-td5VrWBCnSWxFjNrBoDnnRkDfFgq8OjOBaR7k_4zUk41bBikDZ0JOQDWuiaODYBk7PWq0mgotvLPbJ9oc7zfp6lbHqaYXjbzfuD56W_kDYO8zSjiZUGLcYgJDYnO3F8K-QhP02v-0OEpAGrm5SKKV3Txk.Ecojfru8KbkqIw4QvYS3qA";
        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420220122))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        context = consumer.process(jwt);
        jwtClaimsSet = context.getJwtClaimsSet();
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));
    }

    @Test
    public void nestedBackwards() throws Exception
    {
        // a JOT that's a JWE inside a JWS, which is unusual but legal
        String jwt = "eyJjdHkiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.ZXlKNmFYQWlPaUpFUlVZaUxDSmhiR2NpT2lKRlEwUklMVVZUSWl3aVpXNWpJam9pUVRFeU9FTkNReTFJVXpJMU5pSXNJbVZ3YXlJNmV5SnJkSGtpT2lKRlF5SXNJbmdpT2lKYVIwczNWbkZOUzNKV1VGcEphRXc1UkRsT05tTnpNV0ZhYlU5MVpqbHlUWGhtUm1kRFVURjFaREJuSWl3aWVTSTZJbTAyZW01VlQybEtjMnMwTlRaRVVWb3RjVTEzZEVKblpqQkRNVXh4VDB0dk5HYzNjakpGUTBkQllUZ2lMQ0pqY25ZaU9pSlFMVEkxTmlKOWZRLi4xSndRWThoVFJVczdUMFNpOWM1VE9RLkFOdUpNcFowTU1KLTBrbVdvVHhvRDlxLTA1YUxrMkpvRzMxLXdVZ01ZakdaaWZiWG96SDEzZGRuaXZpWXNtenhMcFdVNU1lQnptN3J3TExTeUlCdjB3LmVEb1lFTEhFWXBnMHFpRzBaeHUtWEE.NctFu0mNSArPnMXakIMQKagWyU4v7733dNhDNK3KwiFP2MahpfaH0LA7x0knRk0sjASRxDuEIW6UZGfPTFOjkw";

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420226222))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        JwtClaimsSet jwtClaimsSet = context.getJwtClaimsSet();
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));
        List<JsonWebStructure> joseObjects = context.getJoseObjects();
        assertThat(2, equalTo(joseObjects.size()));
        assertTrue(joseObjects.get(0) instanceof JsonWebEncryption);
        assertTrue(joseObjects.get(1) instanceof JsonWebSignature);

    }

    @Test
    public void testOnlyEncrypted() throws Exception
    {
        // there are legitimate cases where a JWT need only be encrypted but the majority of time a mac'd or signed JWS is needed
        // by default the JwtConsumer should not accept a JWE only JWT to protect against cases where integrity protection might
        // be accidentally inferred

        PublicJsonWebKey sigKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"HVDkXtG_j_JQUm_mNaRPSbsEhr6gdK0a6H4EURypTU0\",\"y\":\"NxdYFS2hl1w8VKf5UTpGXh2YR7KQ8gSBIHu64W0mK8M\",\"crv\":\"P-256\",\"d\":\"ToqTlgJLhI7AQYNLesI2i-08JuaYm2wxTCDiF-VxY4A\"}");
        PublicJsonWebKey encKey = PublicJsonWebKey.Factory.newPublicJwk("{\"kty\":\"EC\",\"x\":\"7kaETHB4U9pCdsErbjw11HGv8xcQUmFy3NMuBa_J7Os\",\"y\":\"FZK-vSMpKk9gLWC5wdFjG1W_C7vgJtdm1YfNPZevmCw\",\"crv\":\"P-256\",\"d\":\"spOxtF0qiKrrCTaUs_G04RISjCx7HEgje_I7aihXVMY\"}");

        String jwt = "eyJ6aXAiOiJERUYiLCJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJ3UXdIa1RUci1tUFpaZURDYU8wRjEwNi1NTkg0aFBfX0xrTW5MaElkTVhVIiwieSI6IkF4Ul9VNW1EN1FhMnFia3R5WS0tU1dsMng0N1gxTWJ5S2Rxb1JteUFVS1UiLCJjcnYiOiJQLTI1NiJ9fQ..oeYI_sIoU1LWIUw3z16V_g.J_BlS-qDJnAqw9wzngIQQioTbTGbyFnorVRq1WTO3leFXKKuBmqoWPHqoVSZdzsVeiFkI-F1DesY489MltwGYg.egjQH2w4oHpMgfjg8saXxQ";

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        expectProcessingFailure(jwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setDecryptionKey(encKey.getPrivateKey())
                .setVerificationKey(sigKey.getPublicKey())
                .setEvaluationTime(NumericDate.fromSeconds(1420219088))
                .setExpectedAudience("canada")
                .setDisableRequireSignature()
                .setExpectedIssuer("usa")
                .setRequireExpirationTime()
                .build();
        JwtContext context = consumer.process(jwt);
        JwtClaimsSet jwtClaimsSet = context.getJwtClaimsSet();
        Assert.assertThat("eh", equalTo(jwtClaimsSet.getStringClaimValue("message")));
    }

    @Test
    public void someBasicAudChecks() throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.parse("{\"aud\":\"example.com\"}");

        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.com").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "example.com", "k8HiI26Y7").build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "nope", "nada").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":\"subject\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience(false, "example.org", "www.example.org").build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience(true, "example.org", "www.example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"aud\":[\"example.com\", \"usa.org\", \"ca.ca\"]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "some.other.junk").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("ca.ca").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("ca.ca", "some.other.thing").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("noway", "ca.ca", "some.other.thing").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca", "random").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca").build();
        goodValidate(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca", "example.com").build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"aud\":[\"example.com\", 47, false]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"aud\":20475}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"aud\":{\"aud\":\"example.org\"}}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
    }

    @Test
    public void someBasicIssChecks() throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.parse("{\"iss\":\"issuer.example.com\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, "issuer.example.com").build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("nope.example.com").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":\"subject\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, "issuer.example.com").build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"iss\":[\"issuer1\", \"other.one\", \"meh\"]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"iss\":[\"issuer1\", \"nope.not\"]}");
        jwtConsumer = new JwtConsumerBuilder().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
    }

    @Test
    public void someBasicSubChecks() throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setRequireSubject().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"name\":\"brian.d.campbell\"}");
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":724729}");
        jwtConsumer = new JwtConsumerBuilder().setRequireSubject().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":{\"values\":[\"one\", \"2\"]}}");
        jwtConsumer = new JwtConsumerBuilder().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
    }

    @Test
    public void someBasicJtiChecks() throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.parse("{\"jti\":\"1Y5iLSQfNgcSGt0A4is29\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setRequireJwtId().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"notjti\":\"lbZ_mLS6w3xBSlvW6ULmkV-uLCk\"}");
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().build();
        goodValidate(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"jti\":55581529751992}");
        jwtConsumer = new JwtConsumerBuilder().setRequireJwtId().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"jti\":[\"S0w3XbslvW6ULmk0\", \"5iLSQfNgcSGt7A4is\"]}");
        jwtConsumer = new JwtConsumerBuilder().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
    }

    @Test
    public void someBasicTimeChecks() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaimsSet jcs = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\"}");
        JwtConsumer consumer = new JwtConsumerBuilder().build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireIssuedAt().build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireNotBefore().build();
        expectValidationFailure(jcs, consumer);


        jcs = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\", \"exp\":1430602000}");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602000)).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602000)).setAllowedClockSkewInSeconds(10).build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601000)).build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430601000)).setAllowedClockSkewInSeconds(6000).build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).setAllowedClockSkewInSeconds(1).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).setAllowedClockSkewInSeconds(2).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).setAllowedClockSkewInSeconds(3).build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430602065)).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602065)).setAllowedClockSkewInSeconds(60).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602065)).setAllowedClockSkewInSeconds(120).build();
        goodValidate(jcs, consumer);


        jcs = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000}");
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430602000)).build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601999)).build();
        expectValidationFailure(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601983)).setAllowedClockSkewInSeconds(30).build();
        goodValidate(jcs, consumer);
        consumer = new JwtConsumerBuilder().setEvaluationTime(NumericDate.fromSeconds(1430601983)).setAllowedClockSkewInSeconds(3000).build();
        goodValidate(jcs, consumer);

        jcs = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000, \"iat\":1430602060, \"exp\":1430602600 }");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setRequireNotBefore().setRequireIssuedAt().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        goodValidate(jcs, consumer);

        jcs = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430603000, \"iat\":1430602060, \"exp\":1430602600 }");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        expectValidationFailure(jcs, consumer);


        jcs = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000, \"iat\":1430602660, \"exp\":1430602600 }");
        consumer = new JwtConsumerBuilder().setRequireExpirationTime().setEvaluationTime(NumericDate.fromSeconds(1430602002)).build();
        expectValidationFailure(jcs, consumer);

    }

    @Test
    public void someBasicChecks() throws InvalidJwtException
    {
        JwtClaimsSet jcs = JwtClaimsSet.parse("{\"sub\":\"subject\", \"iss\":\"issuer\", \"aud\":\"audience\"}");
        JwtConsumer consumer = new JwtConsumerBuilder().setExpectedAudience("audience").setExpectedIssuer("issuer").build();
        goodValidate(jcs, consumer);

        consumer = new JwtConsumerBuilder()
                .setExpectedAudience("nope")
                .setExpectedIssuer("no way")
                .setRequireSubject()
                .setRequireJwtId()
                .build();
        expectValidationFailure(jcs, consumer);
    }

    private void expectProcessingFailure(String jwt, JwtConsumer jwtConsumer)
    {
        try
        {
            jwtConsumer.process(jwt);
            Assert.fail("jwt process/validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            log.debug("Expected exception: " + e);
        }
    }

    private void goodValidate(JwtClaimsSet jwtClaimsSet, JwtConsumer jwtConsumer) throws InvalidJwtException
    {
        jwtConsumer.validate(new JwtContext(jwtClaimsSet, Collections.<JsonWebStructure>emptyList()));
    }

    private void expectValidationFailure(JwtClaimsSet jwtClaimsSet, JwtConsumer jwtConsumer)
    {
        try
        {
            jwtConsumer.validate(new JwtContext(jwtClaimsSet, Collections.<JsonWebStructure>emptyList()));
            Assert.fail("claims validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            log.debug("Expected exception: " + e);
        }
    }
}
