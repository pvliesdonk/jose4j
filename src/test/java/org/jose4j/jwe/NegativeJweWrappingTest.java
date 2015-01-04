package org.jose4j.jwe;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.lang.IntegrityException;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;

/**
 *
 */
public class NegativeJweWrappingTest
{
    Log log = LogFactory.getLog(this.getClass());

    public static final String PAYLOAD = "https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-39#section-11.5";

    @Test
    public void hrm() throws Exception
    {
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setPayload(PAYLOAD);
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey());
        System.out.println(jwe.getCompactSerialization());
    }

    @Test
    public void algSwap() throws Exception
    {
        String cs =
                "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ." +
                "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
                "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
                "iL1wI0-oxEGp3q0RFHiAy_WQ." +
                "DJV9hWkH81InZS1LMGyRMQ." +
                "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBS_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." +
                "s4c-Nx6Dq7rAQrV7Gy7kwQ";
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(cs);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        String payload = jwe.getPayload();
        Assert.assertThat(PAYLOAD, equalTo(payload));

        cs =
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." + // swap in "RSA1_5" alg
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
            "iL1wI0-oxEGp3q0RFHiAy_WQ." +
            "DJV9hWkH81InZS1LMGyRMQ." +
            "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBS_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." +
            "s4c-Nx6Dq7rAQrV7Gy7kwQ";
        expectFailure(cs);

        cs =
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." + // swap in "RSA1_5" alg
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
            "iL1wI0-oxEGp3q0RFHiAy___." +    // change key
            "DJV9hWkH81InZS1LMGyRMQ." +
            "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBa_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." + // change cipher text
            "s4c-Nx6Dq7rAQrV7Gy7kwQ";
        expectFailure(cs);

        cs =
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ." +
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOxCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" + // change key just a little
            "iL1wI0-oxEGp3q0RFHiAy_WQ." +
            "DJV9hWkH81InZS1LMGyRMQ." +
            "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBS_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." +
            "s4c-Nx6Dq7rAQrV7Gy7kwQ";
        expectFailure(cs);

        cs =
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ." +
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
            "iL1wI0-oxEGp3q0RFHiAy_W1." +   // small change to the key
            "DJV9hWkH81InZS1LMGyRMQ." +
            "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBS_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." +
            "s4c-Nx6Dq7rAQrV7Gy7kwQ";
        expectFailure(cs);

        cs =
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ." +
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
            "iL1wI0-oxEGp3q0RFHiAy_WQ." +
            "DJV9hWkH81InZS1LMGyRMQ." +
            "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBS_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." +
            "FlleGhb7Jp-VlWS1wonqsA"; // tag changed
        expectFailure(cs);

        cs =
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ." +
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
            "iL1wI0-oxEGp3q0RFHiAy_WQ." +
            "DJV9hWkH81InZS1LMGyRMQ." +
            "bz2STiMgMpIlBDTVOl6XAzxSzvMzf7K5swoqKvn5sQwDhkCy_NlivPUg7Fxwb9XMII9OrFd_SbsVUeUh9d0h7zsJqVguBtaJ4o0NcW3U2Cs." + // new cipher text
            "s4c-Nx6Dq7rAQrV7Gy7kwQ";
        expectFailure(cs);

        cs =
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ." +   // swap the eng alg
            "ect-RlJEAg9mkPNLJkzBre4Pb5sJ2hY_gzjTT7HlhhmWstkzp_f8u_vVl6s8HeErPtTAopjaVNHdyV6LEmLeKmPYZFaDC63KE7LXz7uV7xodbPZsy83Op9U2DShrsTK0vdRvCVDAA4JvWV9gzN7mMhac2YA9vjf" +
            "GMKXZ_rIXCFX9m7f5qefmRz9LOp6JJYAjbtUHk04_UG4AhG5P3zyBEuQy732CeLJPuJSYtUpPlKVZKfEnABncMOkCr5zkyqFqB9fgV2v-MP6N8rdV16haC_J6wNG0yBG5kCwfS3Pkwh8URI6Fbv5ECS6VuOaG-R" +
            "iL1wI0-oxEGp3q0RFHiAy_WQ." +
            "DJV9hWkH81InZS1LMGyRMQ." +
            "ONRZS2SPKnYF6pkTStZ28T6FxjsruCzLPGH1TOepbBS_bBGYmGI7BZYf6abLdyY6jCJSIMGOv22L1ULJDY53Ek016g_MLyQNWCx88h0J5Qs." +
            "s4c-Nx6Dq7rAQrV7Gy7kwQ";
         expectFailure(cs);
    }

    void expectFailure(String cs) throws JoseException
    {
        // expect the IntegrityException (authn tag issue) for all these different problems
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setCompactSerialization(cs);
        jwe.setKey(ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey());
        try
        {
            String payload = jwe.getPayload();
            Assert.fail("shouldn't have decrypted but got payload: " + payload);
        }
        catch (IntegrityException e)
        {
            log.debug("Expected exception processing modified JWE " + e);
        }
    }
}
