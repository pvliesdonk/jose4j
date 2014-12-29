package org.jose4j.jwt.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.IntDate;
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.hamcrest.CoreMatchers.equalTo;

/**
 *
 */
public class JwtConsumerTest
{
    Log log = LogFactory.getLog(this.getClass());

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
                .setVerificationKey(verificationKey);
        JwtConsumer jwtConsumer = builder.build();

        JwtConsumer.ProcessedJwt processedJwt = jwtConsumer.process(jwt);

        Assert.assertThat(2, equalTo(processedJwt.getJoseObjects().size()));
        Assert.assertTrue(processedJwt.getJoseObjects().get(0) instanceof JsonWebSignature);
        Assert.assertTrue(processedJwt.getJoseObjects().get(1) instanceof JsonWebEncryption);

        JwtClaimsSet jcs = processedJwt.getJwtClaimsSet();

        Assert.assertThat("joe", equalTo(jcs.getIssuer()));
        Assert.assertThat(IntDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));
    }

    @Test
    public void someBasicAudChecks() throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.parse("{\"aud\":\"example.com\"}");

        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.com").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "example.com", "k8HiI26Y7").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("example.org", "nope", "nada").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":\"subject\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience(false, "example.org", "www.example.org").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

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
        jwtConsumer.validateClaims(jwtClaimsSet);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("ca.ca").build();
        jwtConsumer.validateClaims(jwtClaimsSet);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("ca.ca", "some.other.thing").build();
        jwtConsumer.validateClaims(jwtClaimsSet);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("noway", "ca.ca", "some.other.thing").build();
        jwtConsumer.validateClaims(jwtClaimsSet);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca", "random").build();
        jwtConsumer.validateClaims(jwtClaimsSet);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca").build();
        jwtConsumer.validateClaims(jwtClaimsSet);
        jwtConsumer = new JwtConsumerBuilder().setExpectedAudience("usa.org", "ca.ca", "example.com").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

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
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, "issuer.example.com").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("nope.example.com").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":\"subject\"}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer(false, "issuer.example.com").build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtClaimsSet = JwtClaimsSet.parse("{\"iss\":[\"issuer1\", \"other.one\", \"meh\"]}");
        jwtConsumer = new JwtConsumerBuilder().setExpectedIssuer("issuer.example.com").build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
    }

    @Test
    public void someBasicSubChecks() throws InvalidJwtException
    {
        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.parse("{\"sub\":\"brian.d.campbell\"}");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder().build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setRequireSubject().build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtClaimsSet = JwtClaimsSet.parse("{\"name\":\"brian.d.campbell\"}");
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().build();
        jwtConsumer.validateClaims(jwtClaimsSet);

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
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtConsumer = new JwtConsumerBuilder().setRequireJwtId().build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtClaimsSet = JwtClaimsSet.parse("{\"notjti\":\"lbZ_mLS6w3xBSlvW6ULmkV-uLCk\"}");
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
        jwtConsumer = new JwtConsumerBuilder().build();
        jwtConsumer.validateClaims(jwtClaimsSet);

        jwtClaimsSet = JwtClaimsSet.parse("{\"jti\":55581529751992}");
        jwtConsumer = new JwtConsumerBuilder().setRequireJwtId().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);

        jwtClaimsSet = JwtClaimsSet.parse("{\"jti\":[\"S0w3XbslvW6ULmk0\", \"5iLSQfNgcSGt7A4is\"]}");
        jwtConsumer = new JwtConsumerBuilder().build();
        expectValidationFailure(jwtClaimsSet, jwtConsumer);
    }


    @Test
    public void someBasicChecks() throws InvalidJwtException
    {
        JwtClaimsSet jcs = JwtClaimsSet.parse("{\"sub\":\"subject\", \"iss\":\"issuer\", \"aud\":\"audience\"}");
        JwtConsumer consumer = new JwtConsumerBuilder().setExpectedAudience("audience").setExpectedIssuer("issuer").build();
        consumer.validateClaims(jcs);

        consumer = new JwtConsumerBuilder().setExpectedAudience("nope").setExpectedIssuer("no way").build();
        expectValidationFailure(jcs, consumer);
    }

    private void expectValidationFailure(JwtClaimsSet jwtClaimsSet, JwtConsumer jwtConsumer)
    {
        try
        {
            jwtConsumer.validateClaims(jwtClaimsSet);
            Assert.fail("claims validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            log.debug("Expected exception: " + e);
        }
    }
}
