package org.jose4j.jwk;

import junit.framework.TestCase;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.lang.JoseException;

/**
 */
public class RsaJsonWebKeyTest extends TestCase
{
    // key from http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-13#appendix-A.3.1
    // it was shown as octets in -11 and before
    private static final String RSA_JWK_WITH_PRIVATE_KEY =
            "{\"kty\":\"RSA\",\n" +
            " \"n\":\"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\n" +
            "      HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\n" +
            "      D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\n" +
            "      SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\n" +
            "      MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\n" +
            "      NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ\",\n" +
            " \"e\":\"AQAB\",\n" +
            " \"d\":\"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I\n" +
            "      jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0\n" +
            "      BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn\n" +
            "      439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT\n" +
            "      CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh\n" +
            "      BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ\"\n" +
            "}";

    public void testParseExampleWithPrivate() throws JoseException
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(RSA_JWK_WITH_PRIVATE_KEY);
        PublicJsonWebKey pubJwk = (PublicJsonWebKey) jwk;
        assertEquals(ExampleRsaKeyFromJws.PRIVATE_KEY, pubJwk.getPrivateKey());
        assertEquals(ExampleRsaKeyFromJws.PUBLIC_KEY, pubJwk.getPublicKey());
    }

    public void testFromKeyWithPrivate() throws JoseException
    {
        PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(ExampleRsaKeyFromJws.PUBLIC_KEY);
        String jsonNoPrivateKey = jwk.toJson();
        jwk.setPrivateKey(ExampleRsaKeyFromJws.PRIVATE_KEY);
        String dKey = "\"" + RsaJsonWebKey.PRIVATE_EXPONENT_MEMBER_NAME + "\"";
        assertFalse(jwk.toJson().contains(dKey));
        assertEquals(jsonNoPrivateKey, jwk.toJson());

        jwk.setWriteOutPrivateKeyToJson(true);
        assertTrue(jwk.toJson().contains(dKey));
    }
}
