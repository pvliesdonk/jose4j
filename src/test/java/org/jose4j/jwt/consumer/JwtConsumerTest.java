package org.jose4j.jwt.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
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

import static org.hamcrest.CoreMatchers.equalTo;

/**
 *
 */
public class JwtConsumerTest
{
    //TODO more tests - nested and non nested. Unexpected exceptions. Invalid sig. Bad AEAD. Wrong keys. Null keys. 'none' jws good and bad w/ and w/out keys. missing cty. alg constraints. other examples from specs that are JWTs moved here.
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

        JwtConsumer consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS)
                .build();

        JwtClaimsSet jcs = consumer.processToClaims(jwt);
        Assert.assertThat("joe", equalTo(jcs.getIssuer()));
        Assert.assertThat(NumericDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));

        consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .build();
         expectProcessingFailure(jwt, consumer);

        consumer = new JwtConsumerBuilder()
                .setVerificationKey(null)
                .setExpectedIssuer("joe")
                .setRequireExpirationTime()
                .setEvaluationTime(NumericDate.fromSeconds(1300819343))
                .setJwsAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.BLACKLIST, AlgorithmIdentifiers.NONE, AlgorithmIdentifiers.RSA_PSS_USING_SHA256))
                .build();
        expectProcessingFailure(jwt, consumer);

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
