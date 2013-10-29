/*
 * Copyright 2012-2013 Brian Campbell
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

package org.jose4j.jws;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 */
public class ExamplesFromOpenIdConnectTest
{
    @Test
    public void verifySignedRequestObject() throws JoseException
    {
        // OpenID Connect Core 1.0 - draft 15
        // 5.1.  Passing a Request Object by Value has a JWS JWT with a JWK
        String requestObject = 
                "eyJhbGciOiJSUzI1NiJ9.ew0KICJyZXNwb25zZV90eXBlIjogImNvZGUgaWRfdG9rZW" +
                "4iLA0KICJjbGllbnRfaWQiOiAiczZCaGRSa3F0MyIsDQogInJlZGlyZWN0X3VyaSI6I" +
                "CJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYiIsDQogInNjb3BlIjogIm9wZW5p" +
                "ZCIsDQogInN0YXRlIjogImFmMGlmanNsZGtqIiwNCiAibm9uY2UiOiAibi0wUzZfV3p" +
                "BMk1qIiwNCiAibWF4X2FnZSI6IDg2NDAwLA0KICJjbGFpbXMiOiANCiAgew0KICAgIn" +
                "VzZXJpbmZvIjogDQogICAgew0KICAgICAiZ2l2ZW5fbmFtZSI6IHsiZXNzZW50aWFsI" +
                "jogdHJ1ZX0sDQogICAgICJuaWNrbmFtZSI6IG51bGwsDQogICAgICJlbWFpbCI6IHsi" +
                "ZXNzZW50aWFsIjogdHJ1ZX0sDQogICAgICJlbWFpbF92ZXJpZmllZCI6IHsiZXNzZW5" +
                "0aWFsIjogdHJ1ZX0sDQogICAgICJwaWN0dXJlIjogbnVsbA0KICAgIH0sDQogICAiaW" +
                "RfdG9rZW4iOiANCiAgICB7DQogICAgICJnZW5kZXIiOiBudWxsLA0KICAgICAiYmlyd" +
                "GhkYXRlIjogeyJlc3NlbnRpYWwiOiB0cnVlfSwNCiAgICAgImFjciI6IHsidmFsdWVz" +
                "IjogWyIyIl19DQogICAgfQ0KICB9DQp9.bOD4rUiQfzh4QPIs_f_R2GVBhNHcc1p2cQ" +
                "TgixB1tsYRs52xW4TO74USgb-nii3RPsLdfoPlsEbJLmtbxG8-TQBHqGAyZxMDPWy3p" +
                "hjeRt9ApDRnLQrjYuvsCj6byu9TVaKX9r1KDFGT-HLqUNlUTpYtCyM2B2rLkWM08ufB" +
                "q9JBCEzzaLRzjevYEPMaoLAOjb8LPuYOYTBqshRMUxy4Z380-FJ2Lc7VSfSu6HcB2nL" +
                "SjiKrrfI35xkRJsaSSmjasMYeDZarYCl7r4o17rFclk5KacYMYgAs-JYFkwab6Dd56Z" +
                "rAzakHt9cExMpg04lQIux56C-Qk6dAsB6W6W91AQ";

        String jwkJson = "{\n" +
                "   \"kty\":\"RSA\",\n" +
                "   \"n\":\"y9Lqv4fCp6Ei-u2-ZCKq83YvbFEk6JMs_pSj76eMkddWRuWX2aBKGHAtKlE5P\n" +
                "        7_vn__PCKZWePt3vGkB6ePgzAFu08NmKemwE5bQI0e6kIChtt_6KzT5OaaXDF\n" +
                "        I6qCLJmk51Cc4VYFaxgqevMncYrzaW_50mZ1yGSFIQzLYP8bijAHGVjdEFgZa\n" +
                "        ZEN9lsn_GdWLaJpHrB3ROlS50E45wxrlg9xMncVb8qDPuXZarvghLL0HzOuYR\n" +
                "        adBJVoWZowDNTpKpk2RklZ7QaBO7XDv3uR7s_sf2g-bAjSYxYUGsqkNA9b3xV\n" +
                "        W53am_UZZ3tZbFTIh557JICWKHlWj5uzeJXaw\",\n" +
                "   \"e\":\"AQAB\"\n" +
                "  }";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(requestObject);
        jws.setKey(jwk.getKey());
        assertThat(jws.verifySignature(), is(true));
    }


    @Test
    public void verifyIdTokens() throws JoseException
    {
        // OpenID Connect Core 1.0 - draft 15
        // Appendix A.  Authorization Examples has several singed ID Tokens and a JWK
        String idTokenA2 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3Nlc\n" +
                "    nZlci5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyODk3NjEwMDEiLA0KI\n" +
                "    CJhdWQiOiAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNa\n" +
                "    iIsDQogImV4cCI6IDEzMTEyODE5NzAsDQogImlhdCI6IDEzMTEyODA5NzAsD\n" +
                "    QogIm5hbWUiOiAiSmFuZSBEb2UiLA0KICJnaXZlbl9uYW1lIjogIkphbmUiL\n" +
                "    A0KICJmYW1pbHlfbmFtZSI6ICJEb2UiLA0KICJnZW5kZXIiOiAiZmVtYWxlI\n" +
                "    iwNCiAiYmlydGhkYXRlIjogIjAwMDAtMTAtMzEiLA0KICJlbWFpbCI6ICJqY\n" +
                "    W5lZG9lQGV4YW1wbGUuY29tIiwNCiAicGljdHVyZSI6ICJodHRwOi8vZXhhb\n" +
                "    XBsZS5jb20vamFuZWRvZS9tZS5qcGciDQp9.Bgdr1pzosIrnnnpIekmJ7ooe\n" +
                "    DbXuA2AkwfMf90Po2TrMcl3NQzUE_9dcr9r8VOuk4jZxNpV5kCu0RwqqF11-\n" +
                "    6pQ2KQx_ys2i0arLikdResxvJlZzSm_UG6-21s97IaXC97vbnTCcpAkokSe8\n" +
                "    Uik6f8-U61zVmCBMJnpvnxEJllfV8fYldo8lWCqlOngScEbFQUh4fzRsH8O3\n" +
                "    Znr20UZib4V4mGZqYPtPDVGTeu8xkty1t0aK-wEhbm6Hi-TQTi4kltJlw47M\n" +
                "    cSVgF_8SswaGcW6Bf_954ir_ddi4Nexo9RBiWu4n3JMNcQvZU5xMPhu-EF-6\n" +
                "    _nJNotp-lbnBUyxTSg";

        String idTokenA3 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlc\n" +
                "    i5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyODk3NjEwMDEiLA0KICJhdWQiO\n" +
                "    iAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4c\n" +
                "    CI6IDEzMTEyODE5NzAsDQogImlhdCI6IDEzMTEyODA5NzAsDQogImF0X2hhc2giO\n" +
                "    iAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSINCn0.g7UR4IDBNIjoPFV8exQCosUNV\n" +
                "    eh8bNUTeL4wdQp-2WXIWnly0_4ZK0sh4A4uddfenzo4Cjh4wuPPrSw6lMeujYbGy\n" +
                "    zKspJrRYL3iiYWc2VQcl8RKdHPz_G-7yf5enut1YE8v7PhKucPJCRRoobMjqD73f\n" +
                "    1nJNwQ9KBrfh21Ggbx1p8hNqQeeLLXb9b63JD84hVOXwyHmmcVgvZskge-wExwnh\n" +
                "    Ivv_cxTzxIXsSxcYlh3d9hnu0wdxPZOGjT0_nNZJxvdIwDD4cAT_LE5Ae447qB90\n" +
                "    ZF89Nmb0Oj2b1GdGVQEIr8-FXrHlyD827f0N_hLYPdZ73YK6p10qY9oRtMimg";

        String idTokenA4 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlc\n" +
                "    i5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyODk3NjEwMDEiLA0KICJhdWQiO\n" +
                "    iAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4c\n" +
                "    CI6IDEzMTEyODE5NzAsDQogImlhdCI6IDEzMTEyODA5NzAsDQogImNfaGFzaCI6I\n" +
                "    CJMRGt0S2RvUWFrM1BrMGNuWHhDbHRBIg0KfQ.dAVXerlNOJ_tqMUysD_k1Q_bRX\n" +
                "    RJbLkTOsCPVxpKUis5V6xMRvtjfRg8gUfPuAMYrKQMEqZZmL87Hxkv6cFKavb4ft\n" +
                "    BUrY2qUnrvqe_bNjVEz89QSdxGmdFwSTgFVGWkDf5dV5eIiRxXfIkmlgCltPNocR\n" +
                "    AyvdNrsWC661rHz5F9MzBho2vgi5epUa_KAl6tK4ksgl68pjZqlBqsWfTbGEsWQX\n" +
                "    Efu664dJkdXMLEnsPUeQQLjMhLH7qpZk2ry0nRx0sS1mRwOM_Q0Xmps0vOkNn284\n" +
                "    pMUpmWEAjqklWITgtVYXOzF4ilbmZK6ONpFyKCpnSkAYtTEuqz-m7MoLCD_A";


        String idTokenA6 = "eyJhbGciOiJSUzI1NiJ9.ew0KICJpc3MiOiAiaHR0cDovL3NlcnZlc\n" +
                "    i5leGFtcGxlLmNvbSIsDQogInN1YiI6ICIyNDgyODk3NjEwMDEiLA0KICJhdWQiO\n" +
                "    iAiczZCaGRSa3F0MyIsDQogIm5vbmNlIjogIm4tMFM2X1d6QTJNaiIsDQogImV4c\n" +
                "    CI6IDEzMTEyODE5NzAsDQogImlhdCI6IDEzMTEyODA5NzAsDQogImF0X2hhc2giO\n" +
                "    iAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSIsDQogImNfaGFzaCI6ICJMRGt0S2RvU\n" +
                "    WFrM1BrMGNuWHhDbHRBIg0KfQ.JQthrBsOirujair9aD5gj1Yd5qEv0j4fhLgl8h\n" +
                "    3RaH3soYhwPOiN2Iy_yb7wMCO6I3bPoGJc3zCkpjgUtdB4O2eEhFqXHdwnE4c0oV\n" +
                "    TaTHJi_PdV2ox9g-1ikDB0ckWk0f0SzBd7yM2RoYYxJCiGBQlsSSRQz6ehykonI3\n" +
                "    hLAhXFdpfbK-3_a3HBNKOv_9Mr_JJrz2pqSygk5IBNvwzf1ouVeM91KKvr7EdriK\n" +
                "    N8ysk68fctbFAga1p8rE3cfBOX7Acn4p9QSNpUx0i_x4WHktyKDvH_hLdUw91Fql\n" +
                "    _UOgMP_9h8TYdkAjcq8n1tFzaO7kVaazlZ5SM32J7OSDgNSA";

        String jwkJson = "  {\n" +
                "   \"kty\":\"RSA\",\n" +
                "   \"n\":\"zhEWTBJVTfcUeqnMzOQFMCEVQWOyOUZwP8LrBWh88tKrZyPGCvBkTDp-E2Bzy\n" +
                "        HMQV4pK51Uys2YOwzL9se5THDWMda9rtsCJVcj1V7WaE7wPgl-kIIdWWf4o2g\n" +
                "        6ZszOy_Fp4q0nG3OTtDRCkBu2iEP21j82pRSRrkCBxnzaChflA7KZbI1n_yhK\n" +
                "        txyA7FdA480LaSVZyKApvrKiYhocACSwf0y6CQ-wkEi6mVXRJt1aBSywlLYA0\n" +
                "        8ojp5hkZQ39eCM2k1EdXdhbar998Q9PZTwXA1cfvuGTZbDWxEKLjMKVuKrT1Y\n" +
                "        vs-2NTXhZAW1KjFS_3UwLkDk-w4dVN-x5tDnw\",\n" +
                "   \"e\":\"AQAB\"\n" +
                "  }";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

        for (String idToken : new String[] {idTokenA2, idTokenA3, idTokenA4, idTokenA6})
        {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(idToken);
            jws.setKey(jwk.getKey());
            assertThat(jws.verifySignature(), is(true));
            System.out.println(jws.getPayload());
        }
    }
}
