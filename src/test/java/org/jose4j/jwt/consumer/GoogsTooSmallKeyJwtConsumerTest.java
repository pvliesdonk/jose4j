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

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class GoogsTooSmallKeyJwtConsumerTest
{
    /**
     * ~ May 2015 Google's JWKS URI https://www.googleapis.com/oauth2/v3/certs for OIDC had 1024 bit RSA keys in it that were being used to sign ID tokens.
     * That goes against the min of 2048 in https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.3
     * "A key of size 2048 bits or larger MUST be used with [RS256, etc]"
     *
     * These are some tests to check that we do, by default, enforce the key size (it's been that way for a long time) but that there are easy workarounds
     * possible at the JwtConsumer[Builder] layer.
     *
     * The example content was from Google May 14th '15
     *
     * A bug report was submitted to them on May 19 2-4355000007039 but we'll see if anything comes of it.  Exposing the setRelaxXXXKeyValidations on JwtConsumer[Builder]
     * will probably be useful in other ways.
     */

    static String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc2ZmQzMmFlYzdlMGY4YzE5MGRkYThiOWRkODVlN2NmNWFkMzNjNDMifQ" +
            ".eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwic3ViIjoiMTE2MzA4NDA4MzE0NjYxNDc4MTMyIiwiYXpwIjoiODIyNzM3NTU1NDI5LWV2dmtkMDBvdHFyNWdsMTEwbmZhcGlzamZvZWEzNmpmLmFwcHMuZ29vZ2xldXNlcmNvb" +
            "nRlbnQuY29tIiwiZW1haWwiOiJqa3Rlc3QxQG1hcml0aW1lc291cmNlLmNhIiwiYXRfaGFzaCI6Im85bUZjZUx6QV9ZMnhmNEJqVmdOQmciLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXVkIjoiODIyNzM3NTU1NDI5LWV2dmtkMDB" +
            "vdHFyNWdsMTEwbmZhcGlzamZvZWEzNmpmLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaGQiOiJtYXJpdGltZXNvdXJjZS5jYSIsIm9wZW5pZF9pZCI6Imh0dHBzOi8vd3d3Lmdvb2dsZS5jb20vYWNjb3VudHMvbzgvaWQ_a" +
            "WQ9QUl0T2F3bGIxSEhFZFJJZW00d2Z1MXFNY1BUdWZvUDZzTi11ZVVrIiwiaWF0IjoxNDMxNjEyMjM4LCJleHAiOjE0MzE2MTU4Mzh9" +
            ".RRMVpR9WJrkddegS4uKNT7rTov-LvRQ9sCtGo_SXrqkNbLZgArSJcmmHHxoQDsVWUjl2ZNG-7ZjDRuMu-POJLR4GHpwmQ8gttAEeywkiW4in5pUOb21AdgH29HDwG2mY6iVavsASHRutK747gURRlpt3wUJOJk00T9W2N0fVsTE";

    static String JWKS_JSON = "{ \"keys\": [\n" +
            "  {\n" +
            "   \"kty\": \"RSA\",\n" +
            "   \"alg\": \"RS256\",\n" +
            "   \"use\": \"sig\",\n" +
            "   \"kid\": \"76fd32aec7e0f8c190dda8b9dd85e7cf5ad33c43\",\n" +
            "   \"n\": \"03TVzpSoWDe8iPqvAde1JmmITIHD6JU8Koy10fSUW0u1QO6fle93GxHOHeQmP7FBhLSy5gWK23za38kN0KMucYGOjcWOwnO_pTQrCXxFzD-HBy_IiRyRkhuaQXsKvpJbblMEmcfeR4cWlzKt9RKjjXBl5bmIiLrN167iftlR84E\",\n" +
            "   \"e\": \"AQAB\"\n" +
            "  },\n" +
            "  {\n" +
            "   \"kty\": \"RSA\",\n" +
            "   \"alg\": \"RS256\",\n" +
            "   \"use\": \"sig\",\n" +
            "   \"kid\": \"317b5931c783031d970c1a2552266215598a9814\",\n" +
            "   \"n\": \"sxAi31Tz53-HtjmVlGpyNEGO8MtL-uvwdKDG__a-gPYE8WGEQQgpBXjjFqmIsfs-yd8YHYw0uCJwAu-ILT1AbhVTZiEEnrLKNTc_gPqfveZxnySJCguVx1pWpZ0q9cBMdgvetrbUfRO2Sz1YFgfD7k9BacWwOM-eiFtgrWwOTo8\",\n" +
            "   \"e\": \"AQAB\"\n" +
            "  }\n" +
            " ]\n" +
            "}";

    static final String CLIENT_ID = "822737555429-evvkd00otqr5gl110nfapisjfoea36jf.apps.googleusercontent.com";
    static final String ISSUER = "accounts.google.com";
    static final NumericDate EVALUATION_TIME = NumericDate.fromSeconds(1431612438);
    static final String SUBJECT_VALUE = "116308408314661478132";

    @Test
    public void strictByDefault() throws JoseException
    {
        JsonWebKeySet jwks = new JsonWebKeySet(JWKS_JSON);
        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setEvaluationTime(EVALUATION_TIME)
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(ISSUER)
                .setExpectedAudience(CLIENT_ID) // to whom the JWT is intended for
                .setVerificationKeyResolver(verificationKeyResolver) // pretend to use Google's jwks endpoint to find the key for signature checks
                .build(); // create the JwtConsumer instance

        SimpleJwtConsumerTestHelp.expectProcessingFailure(ID_TOKEN, jwtConsumer);
    }


    @Test
    public void firstWorkaroundUsingTwoPass() throws Exception
    {
        // Build a JwtConsumer that doesn't check signatures or do any validation.
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
        JwtContext jwtContext = firstPassJwtConsumer.process(ID_TOKEN);

        // turn off key key validation (chiefly the enforcement of RSA 2048 as min key size) on the the inner most JOSE object (the JWS)
        jwtContext.getJoseObjects().iterator().next().setDoKeyValidation(false);

        JsonWebKeySet jwks = new JsonWebKeySet(JWKS_JSON);
        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setEvaluationTime(EVALUATION_TIME)
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(ISSUER)
                .setExpectedAudience(CLIENT_ID) // to whom the JWT is intended for
                .setVerificationKeyResolver(verificationKeyResolver) // pretend to use Google's jwks endpoint to find the key for signature checks
                .build(); // create the JwtConsumer instance

        jwtConsumer.processContext(jwtContext);
        JwtClaims jwtClaims = jwtContext.getJwtClaims();
        assertThat(SUBJECT_VALUE, equalTo(jwtClaims.getSubject()));
    }

    @Test
    public void newerWorkaroundOnConsumerBuilder() throws Exception
    {
        JsonWebKeySet jwks = new JsonWebKeySet(JWKS_JSON);
        JwksVerificationKeyResolver verificationKeyResolver = new JwksVerificationKeyResolver(jwks.getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRelaxVerificationKeyValidation() // **THIS** is what will tell the underlying JWS to not check the key too much and allow the 1024
                .setRequireExpirationTime()
                .setEvaluationTime(EVALUATION_TIME)
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(ISSUER)
                .setExpectedAudience(CLIENT_ID) // to whom the JWT is intended for
                .setVerificationKeyResolver(verificationKeyResolver) // pretend to use Google's jwks endpoint to find the key for signature checks
                .build(); // create the JwtConsumer instance

        JwtClaims claims = jwtConsumer.processToClaims(ID_TOKEN);
        assertThat(SUBJECT_VALUE, equalTo(claims.getSubject()));
    }
}
