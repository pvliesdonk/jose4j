package org.jose4j.jwx;

import junit.framework.TestCase;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;

/**
 */
public class HeadersTest extends TestCase
{
    public void testRoundTripJwkHeader() throws JoseException
    {
        Headers headers = new Headers();

        String ephemeralJwkJson = "\n{\"kty\":\"EC\",\n" +
                " \"crv\":\"P-256\",\n" +
                " \"x\":\"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0\",\n" +
                " \"y\":\"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps\",\n" +
                " \"d\":\"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo\"\n" +
                "}";
        PublicJsonWebKey ephemeralJwk = PublicJsonWebKey.Factory.newPublicJwk(ephemeralJwkJson);

        String name = "jwk";
        headers.setJwkHeaderValue(name, ephemeralJwk);

        JsonWebKey jwk = headers.getJwkHeaderValue(name);

        assertEquals(ephemeralJwk.getKey(), jwk.getKey());

        String encodedHeader = headers.getEncodedHeader();

        Headers parsedHeaders = new Headers();
        parsedHeaders.setEncodedHeader(encodedHeader);

        JsonWebKey jwkFromParsed = parsedHeaders.getJwkHeaderValue(name);
        assertEquals(ephemeralJwk.getKey(), jwkFromParsed.getKey());
    }
}
