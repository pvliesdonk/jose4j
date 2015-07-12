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

import org.hamcrest.CoreMatchers;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.resolvers.JwksDecryptionKeyResolver;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

/**
 *
 */
public class JwksDecryptionKeyResolverUsingJwtConsumerTest
{
	private static final Logger log = LoggerFactory.getLogger(JwksDecryptionKeyResolverUsingJwtConsumerTest.class);
	
    @Test
    public void testSymmetricKeysWithDir() throws JoseException, InvalidJwtException, MalformedClaimException
    {
        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"SGfpdt9Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"}," +
                "{\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"Fvlp7BLzRr-a9pOKK7BA25om7u6cY2o9Lz6--UAFWXw\"}," +
                "{\"kty\":\"oct\",\"kid\":\"tres\",\"k\":\"izcqzDJd6-7rP5pnldgK-jcDjT6xXdo3bIjwgeWAYEc\"}]}";
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);

        String jwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9" +
                "." +
                ".JruwzL7TaQ1Fub8Hw6yYmQ" +
                ".b4B9F3kerVHvyGB5zb40lkTqxulLbMhwFi-qvPfFwwbuyPVPf5s7TeT3i3MLRs0-l_1hP5bPxIEEnOEOBbqTGwO1TWuBn_lQsR8XpQRp6t4H0eaXZsnBqOa3MeEtmGpo" +
                ".Hzbvc--4g2nqIaYoYkc2pQ";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424015558))
                .setRequireExpirationTime()
                .setExpectedIssuer("from")
                .setExpectedAudience("to")
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setDisableRequireSignature()
                .build();

        JwtContext jwtCtx = jwtConsumer.process(jwt);
        Assert.assertThat(jwtCtx.getJoseObjects().size(), CoreMatchers.equalTo(1));
        Assert.assertThat(jwtCtx.getJwtClaims().getSubject(), CoreMatchers.equalTo("Scott Tomilson, not Tomlinson"));

        String badJwt = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9" +
                "." +
                ".JruwzL7TaQ1Fub8Hw6yYmQ" +
                ".b4B9F3kerVHvyGB5zb40lkTqxulLbMhwFi-qvPfFwwbuyPVPf5s7TeT3i3MLRs0-l_1hP5bPxIEEnOEOBbqTGwO1TWuBn_lQsR8XpQRp6t4H0eaXZsnBqOa3MeEtmGpo" +
                ".Hzbvc__4g2nqIaYoYkc___";  // bad tag

        try
        {
            JwtClaims claims = jwtConsumer.processToClaims(badJwt);
            fail("shouldn't have processed/validated but got " + claims);
        }
        catch (InvalidJwtException e)
        {
        	log.debug("this was expected and is okay: {}", e.toString());
        }

        json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"one\",\"k\":\"SGfpdt9Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"}," +
                "{\"kty\":\"oct\",\"kid\":\"two\",\"k\":\"izcqzDJd6-7rP5pnldgK-jcDjT6xXdo3bIjwgeWAYEc\"}]}";
        jsonWebKeySet = new JsonWebKeySet(json);
        jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424015558))
                .setRequireExpirationTime()
                .setExpectedIssuer("from")
                .setExpectedAudience("to")
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setDisableRequireSignature()
                .build();

        try
        {
            JwtClaims claims = jwtConsumer.processToClaims(jwt);
            fail("shouldn't have processed/validated but got " + claims);
        }
        catch (InvalidJwtException e)
        {
            log.debug("this was expected and is okay: {}", e.toString());
        }
    }

    @Test
    public void testSymmetricKeysWithAesWrap() throws Exception
    {
        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"1one\",\"k\":\"_-cqzgJ-_aeZkppR2JCOlx\"}," +
                "{\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"mF2rZpj_Fbeal5FRz0c0Lw\"}," +
                "{\"kty\":\"oct\",\"kid\":\"tres\",\"k\":\"ad2-dGiApcezx9310j4o7W\"}]}";
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);

        String jwt = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiZGV1eCJ9" +
                ".UHa0kaUhz8QDHE_CVfpeC-ebzXapjJrQ5Lk4r8XvK1J5WD32UeZ3_A" +
                ".3pPAmmVX_elO_9lgfJJXiA" +
                ".8pNNdQ_BsTwFicdrCevByA4i7KAzb__qF6z6olEQ3M8HayMAwOJoeF0yhnkM0JcydcCiULRE_i8USvpXWiktBhIJ79nDlqHxK09JB6YGnkpBMZgAmWf1NJFmTlF4vRs6" +
                ".3_UixCVYQsUablSjTX8v2A";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424026062))
                .setRequireExpirationTime()
                .setExpectedIssuer("from")
                .setExpectedAudience("to")
                .setDecryptionKeyResolver(new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys()))
                .setDisableRequireSignature()
                .build();

        JwtContext jwtCtx = jwtConsumer.process(jwt);
        Assert.assertThat(jwtCtx.getJoseObjects().size(), CoreMatchers.equalTo(1));
        Assert.assertThat(jwtCtx.getJwtClaims().getSubject(), CoreMatchers.equalTo("Scott Tomilson, not Tomlinson"));
    }

    @Test
    public void testAsymmetricDecryptionKeys() throws Exception
    {
        String octKeysJson = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"uno\",  \"k\":\"aSqzs8KJZgnYb9c7d0zgdACK0-i0Hi3K-jcDjt8V0aF9aWY8081d1i2c33pzq5H5eR_JbwmAojgUl727gGoKz7\"}," +
                "{\"kty\":\"oct\",\"kid\":\"two\", \"k\":\"-v_lp7B__xRr-90pNCo7u6cY2o9Lz6-P--_0TWhAI4vMQFh6WeZu0fM4lui0Hi3K-jcDjt8V0aF9aWY0081dc1c\"}," +
                "{\"kty\":\"oct\",\"kid\":\"trois\",\"k\":\"_pMndrQmbXEK0-i0Hi3K-jcdDjt89Lz6-c_1_01ji-41ccx6-7rPpCK0-i0HiV0aFcc9d8bcKic10_aWY8081d\"}]}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(octKeysJson);
        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jsonWebKeySet.getJsonWebKeys());

        String decryptionKeysJson = "{\"keys\":[" +
                "{\"kty\":\"EC\",\"kid\":\"001\",\"x\":\"B8j3GQhgSvxDitJ7GtDQ_b5lFRIUl98T7TYuYLNQg4k\",\"y\":\"3P0i0nFQMng4OT3BrylKCtO4yQaXm6s-oGUYBf1u6hs\",\"crv\":\"P-256\",\"d\":\"vd2hw-2_RiBcQiUYomQIr6OwxRiLhiRG3yUjWUIaphI\"}," +
                "{\"kty\":\"EC\",\"kid\":\"003\",\"x\":\"q-EZUCCzI3Kvr6D_ZbH_W2PZa-GzamxAQeOTXEyiviA\",\"y\":\"PkdfdW-XCwO7y1vM69Y-vw3L8RfM6EfLs_49uzd605I\",\"crv\":\"P-256\",\"d\":\"UhUxGGxCj4V6oZg-za85XJ0sHa9xgExMVxAXEh5eVOw\"}," +
                "{\"kty\":\"EC\",\"kid\":\"003\",\"x\":\"q-EZUCCzI3Kvr6D_ZbH_W2PZa-GzamxAQeOTXEyiviA\",\"y\":\"PkdfdW-XCwO7y1vM69Y-vw3L8RfM6EfLs_49uzd605I\",\"crv\":\"P-256\",\"d\":\"UhUxGGxCj4V6oZg-za85XJ0sHa9xgExMVxAXEh5eVOw\"}]}";
        jsonWebKeySet = new JsonWebKeySet(decryptionKeysJson);
        JwksDecryptionKeyResolver decryptionKeyResolver = new JwksDecryptionKeyResolver(jsonWebKeySet.getJsonWebKeys());

        String jwt = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImtpZCI6IjAwMyIsImN0eSI6Imp3dCIsImVwayI6eyJrdHkiOiJFQyIsIngiOiJqUGRiMlU4a0FJSTRRMXBjSnVHZS0yNlcyQ0NVNlNFTnhJX0JRWWh0X3M4IiwieSI6IlVSUjg5MmZDVGtUSFZ2cUFuYXpWa01QMFNQNFVyUUYtODFLVm9OV3p2WEkiLCJjcnYiOiJQLTI1NiJ9fQ" +
                "..YSs9jK_K7W9KPkXT379C-A" +
                ".NyWNDnO9y8xELimQpBYX55apvVDP0tUdqQqMOnYMZQVZ4rRKWfyoS9830IVZhE79hfMltPX0mK_5vj_NByH8rQV2gRHx4hv_off96Jq3dnlyUofwN5bleUKZLs14BgopG15lAkmOtsRfoxN56ZXTL9FWitcKYYTXbLcw5UPIM6nTePRJoh2ZAZpqBA7FJKX3aNBm9851zjDPFyTCLSMmCyFuqzeZGrF_Ic-KHSjVnwgslPW5Kca_XunQilEs9VWlinoSpf0HxqQRogGQIi8EmA" +
                ".flt8CcaCXWa23Ci5EhLdNw";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setEvaluationTime(NumericDate.fromSeconds(1424266660))
                .setExpectedAudience("TO")
                .setExpectedIssuer("FROM")
                .setRequireExpirationTime()
                .setRequireSubject()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setDecryptionKeyResolver(decryptionKeyResolver)
                .build();

        JwtClaims claims = jwtConsumer.processToClaims(jwt);
        assertThat("ABOUT", equalTo(claims.getSubject()));
    }

}
