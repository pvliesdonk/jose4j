package org.jose4j.jwk;

import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;

/**
 *
 */
public class JsonWebKeySetAnotherTest
{
    @Test
    public void oneBadApple() throws JoseException
    {
        // one of the 4 jwks is missing a required parameter
        // rather than rejecting the whole thing, we want to just ignore the problematic key
        String json =
                "{" +
                "  \"keys\": [" +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"96\"," +
                "      \"x\": \"bfOKLR8w_vD7ce9o_hmxfqTcNo9joJIALo4xC_-Qhzg\"," +
                "      \"y\": \"y2jXZtCaeoLGQIiJx5-kHLT3SlP7nzQbnP8SLUl1vg4\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"a9\"," +
                "      \"x\": \"msdBj_jUyuw_qCkNXTGjGpibVc_FE5FaexmE_qTWKmY\"," +
                "      \"y\": \"lDHAX8xJ17zRDtPcPzQmFurVtOJllmOK2jPwCGZ57TQ\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"this one shouldn't work 'cause there's no y\"," +
                "      \"x\": \"msdBj_jUyuw_qCkNXTGjGpibVc_FE5FaexmE_qTWKmY\"," +
                "      \"crv\": \"P-256\"" +
                "    }," +
                "    {" +
                "      \"kty\": \"EC\"," +
                "      \"kid\": \"2d\"," +
                "      \"x\": \"l3V6TH8tuS0vWSpZ9KcUW4oDuBzOTN0v2C_dsqkrHKw\"," +
                "      \"y\": \"Yhg6pR__nALI6sp68NcQM6FlPaod83xUXgHKGOCJHJ4\"," +
                "      \"crv\": \"P-256\"" +
                "    }" +
                "  ]" +
                "}";
        JsonWebKeySet jwks = new JsonWebKeySet(json);
        Assert.assertThat(3, equalTo(jwks.getJsonWebKeys().size()));
    }
}
