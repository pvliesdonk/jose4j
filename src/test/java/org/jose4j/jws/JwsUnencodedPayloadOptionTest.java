package org.jose4j.jws;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.StringUtil;
import org.junit.Test;

import java.security.Key;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class JwsUnencodedPayloadOptionTest
{
    @Test
    public void testExamplesFromDraftEvenWithoutDirectSupportForTheHeader() throws Exception
    {
        // a test of sorts to verify the examples from
        // http://tools.ietf.org/html/draft-ietf-jose-jws-signing-input-options-09#section-4
        // at Mike's request

        String jwkJson =
                "{" +
                "  \"kty\":\"oct\"," +
                "  \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75" +
                "      aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"" +
                "}";
        final JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(jwkJson);
        final Key key = jsonWebKey.getKey();

        String payload = "$.02";

        final String encodedPayload = Base64Url.encode(payload, StringUtil.US_ASCII);
        assertThat(encodedPayload, equalTo("JC4wMg"));

        String jwscsWithB64 = "eyJhbGciOiJIUzI1NiJ9.JC4wMg.5mvfOroL-g7HyqJoozehmsaqmvTYGEq5jTI1gVvoEoQ";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwscsWithB64);
        jws.setKey(key);
        assertThat(jws.getPayload(), equalTo(payload));
        assertTrue(jws.verifySignature());

        jws = new JsonWebSignature();
        jws.setPayload(payload);
        jws.setKey(key);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        assertThat(jws.getCompactSerialization(), equalTo(jwscsWithB64));

        String jwscsWithoutB64andDetachedPaylod = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.." +
                "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY";

        jws = new JsonWebSignature();
        jws.setCompactSerialization(jwscsWithoutB64andDetachedPaylod);
        assertThat(jws.getHeaders().getFullHeaderAsJsonString(), equalTo("{\"alg\":\"HS256\",\"b64\":false,\"crit\":[\"b64\"]}"));

        HmacUsingShaAlgorithm.HmacSha256 hmacSha256 = new HmacUsingShaAlgorithm.HmacSha256();

        final String signingInputString = jws.getHeaders().getEncodedHeader() + "." + payload;

        final byte[] signatureBytes = Base64Url.decode(jws.getEncodedSignature());
        final byte[] securedInputBytes = StringUtil.getBytesAscii(signingInputString);
        final ProviderContext providerContext = new ProviderContext();
        boolean okay = hmacSha256.verifySignature(signatureBytes, key, securedInputBytes, providerContext);
        assertTrue(okay);

        final byte[] signed = hmacSha256.sign(key, securedInputBytes, providerContext);
        assertThat(Base64Url.encode(signed), equalTo(jws.getEncodedSignature()));
    }
}
