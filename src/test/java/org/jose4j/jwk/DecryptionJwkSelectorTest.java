package org.jose4j.jwk;


import org.jose4j.base64url.Base64Url;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

/**
 *
 */
public class DecryptionJwkSelectorTest
{
    // todo tests w/ x5t stuff

    @Test
    public void someSelections() throws Exception
    {
        String json =
            "{\n" +
            "  \"keys\": [\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"kid\": \"rSK-0_k\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"x\": \"qQGegqPCpvi9tLJF_ofPR6PJIRb-OgZX3n8TKwR5a30\",\n" +
            "      \"y\": \"HQAAFdTf3O1egAoYGmsPDjaIYdeS6Gm-Dv175yim4OM\",\n" +
            "      \"crv\": \"P-256\",\n" +
            "      \"d\": \"aI6PD_LfL4lFUdyAHFnRSUYhBL_8k7gxfoDXeWiI1Gs\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"kid\": \"KGAbCMI\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"x\": \"nfXylbOqF7aW5wnMzc5mWuSgx5Kfkx8wXw62ZTxVhmQRP_2XfV5hE_ek-AxOI4UG\",\n" +
            "      \"y\": \"s-cIx-W0y7Aep7dxiArL_n3HSBODcvUyNBc510OiAOFkV6J_wNcb5QokT9LsKRYi\",\n" +
            "      \"crv\": \"P-384\",\n" +
            "      \"d\": \"iSs9l_3Tlyeco1LzblzPoOdcvLYZum4hY75M9b0fCrULhqSIeyXu53THp-wZ_Hdt\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"kid\": \"4AFzkhA\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"x\": \"AcZBC-sgcJpUjP3P6wUNYW1nBH8AduQi_vjjOgaFg-35_ZYDUckp0yw4BnpKEQvueYmbNoEVpf4dWslLhiWtxHRR\",\n" +
            "      \"y\": \"AJcl35TUpqKJTmrRDW3MiC5gxuAteeBwHofnTXA5JhSbUKxEAx0hMuRcRgMHV47MqwxriEReR06Vhk152eh4tTOL\",\n" +
            "      \"crv\": \"P-521\",\n" +
            "      \"d\": \"AdJ-14bVfrfErJjkfPuwTzbeLeZN9Doqb6mOPwSZYDReMoGgXa0d44X4d53lYAC1nQHLyLjXt3A8KIjXWwwdnSsi\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"RSA\",\n" +
            "      \"kid\": \"Lu8lh94\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"n\": \"rgS8RROXfdBwXMfU9NMMw-m-HfWRDSZU6Vmhbqrd4jOGwHlbKNcEy7U5-FaTBp1JLXOdR4sYmY2TdU36GapWYPQtVqqUUhPxudBlmP9JkMG9XC25N-O0-hIp2F40tMGHTcdOo8nb6UgPFV96XJsCUrODdtXDKBt7o50ahLjql_iXP0QxlX-kPcd-ANKIRVBJa7VPKf9xH1iF6bvAio8SgHB2QXancd9CmobisPhqbck6Szv5SxhPTQ3ZV5aRP8UB9fCBvbD8POQY-YqF1xNo7qwosX2PC-Q0ejn4Saf3jwE79stybi-JIytRs93YUh3w3LLzGqprMHdUqNc01-h1Ew\",\n" +
            "      \"e\": \"AQAB\",\n" +
            "      \"d\": \"NFiUUasdDOmggyhRdPvvgRdU6yotYek_7Znap7GaYSrixA89TsGvXZ-8OmnAfGLf2l5G13iOA9LEoqq8KvBEX5HT-ZgCWdZKBn0bsrRIatT8ozfV2WwTyo2gLMfZzu3QR6NGkppsHnZgoys_YY_3WO1LBHo05GGwBX2Ctp3xY5kS2rgUlbnWx2FbNsnokR6dD1PordCMNiSgg_r3l3dB4FbDI_7Xi8n4XH9vIf6wd60FRhtNChS1Ybrny0GadHUvUKshnnwaCfda2u3iY4qI8mRiH6a9zg2943peLxNlSegZ9ceCQAGAXPhC77B3Nth4K4JDsHLD6ItrLFIOt6A2gQ\",\n" +
            "      \"p\": \"0xnpS1_Dj5A4QCRgFPEryaA-kQmes6fpSaP9ETncvTQ4LduSdMsLua5-6FF_FV50cgtOUvYh7DiR93Xq_GVC9Bp1TOmsTRqquMUBcvKBWUto2dxGuqnjfQLgEfxLGOhK98EDff1tATP5eZ-7aONvlIhrDUyKqCgZLUnvVi3s7qE\",\n" +
            "      \"q\": \"0we8TQ8ivTdp9wkGfuyu5f4zCQFuFsyVdO8jEd77m2ZWumBpYpYvV34Lg9IqeiRtNX8pQ-Hi8QIKXhnAE55-KU-emgSJVtR_50da59BTq-VD0heCBhuTA6aDCu3Yb9chbRcxlIIp-GJlS2sRisoGzlgKgwAw5fkhnj7DXdL0CzM\",\n" +
            "      \"dp\": \"PVovgnd_l67bmlC4F_4Lstq-tFpuZFpto7hkaWg-rkKJ_VHuW8FTVBDR02U0IRrFjwuYJOZh74x1Z80-kUJA1j8GTmcva21Ppsmi5SxzyWbwPzkU2VVcx01ZoACKNt_0QdM315sa3hmj7OQujIplOG75ZfET71FQF-iABbTtQmE\",\n" +
            "      \"dq\": \"AZS-QWmKnhZLMfGcXdkSGmEEKt4a4AraV8zu21RrWCe1IKJWR8nOQv6LwYoSjWW2d78jJQINPDcCst_Ig50dXtvc2VSNXtwqtSXgtXnnFpOaJXnNnJQaTt2xf6R2iaf39SRGV9F91QGPtrfvorWOxX79XSvkMeTi7peTySEqeOc\",\n" +
            "      \"qi\": \"ENCxJaHcPIBu5JObYrt0Qf4ZEj2aEFMOdtbijj8Eykx4XD6I-sosG1XWfKl6JV3-fR8OwTyS_KZyj0dEOtpRSkM3bzuc24WMt3xt7pkf7uCjTU9H_rX475cf5wog7f1qQHdy3FkCqAgXTBThPCrObWKBQKGQRTD-rzUKZMu4Qmk\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"kid\": \"y-d_6-Q\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"x\": \"6vuZ4sXwcZakG-to24OTl9ausKXBwhJ07wPzcYPamMc\",\n" +
            "      \"y\": \"S5oijwbmu6323BE1nyxsLALR5cvjKisLmPVmrlMOkvg\",\n" +
            "      \"crv\": \"P-256\",\n" +
            "      \"d\": \"WGbj9NHJi32wFKCCDdlaTg4Wz4A3iOwz2GTJmLM6Tq8\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"kid\": \"MShX4q0\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"x\": \"ERK0_wI9OC_vPvWTgN4CSgoZjuSVne599eI3rucN_I5ieOpm823fXAidM3hisQ0z\",\n" +
            "      \"y\": \"G3ez7AwleHtpDSF4yv29_wmZQmQJaoJEXFFlzw40rGPVsrIVM8EaAkCExR2vL1Ln\",\n" +
            "      \"crv\": \"P-384\",\n" +
            "      \"d\": \"j7s4vyEhlhdQaY0XiMf018AtIzxvov0nPVw8M3BCwiTYl0q-dkjlWOvQh_ShSE5b\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"kid\": \"2biZ7iQ\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"x\": \"ASPDR6Z0yPPf5WQ1vrg4hDwCG7nCna2AhkwvVlrIi3THrouRaIyPfvfDyJ7_kGvxulpqivLdHaeP4FGqO0FZYjaO\",\n" +
            "      \"y\": \"AYe-9LyCnARzja54KxX6jymGMUg3r3jzw8PWaKopXh-KLYaMSVwybvggkOs6LSjgggVUaP3oY2OlygT6Fc7df3TC\",\n" +
            "      \"crv\": \"P-521\",\n" +
            "      \"d\": \"ADMehHHdfUWURufhVzalzB5yp1z5XOGg0FP4kUKt4s7FQ82bB58ALxB1DgWc57HYeTk3-DQeoll8etSDxbnBvRo7\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"RSA\",\n" +
            "      \"kid\": \"U-DESNk\",\n" +
            "      \"use\": \"enc\",\n" +
            "      \"n\": \"idpTcmw_zbbL7GYHYnGXI5znbti4h4eBwov3qOYmCb-_Tl3yJLkff018nu9WLb7TFUC7sazfIIOvP6RVURLD5h39PwumJKZNtZ9qQZxjbaT3uWrEiDb9mb6UXW-zGU38f4XwGgqNfCdT1nBmCprJsljVt12hqGEuMQGW5R5jalXnrAj-wGkuJQ2r5SN7THTelrmHEg37Ft-D8htO5ubUwMN4sslRICEX6FlB0yqG880tLK28j8EYftnDsKs-bfS_md_pxq03sebMVN9pqcTC0bXh9q0_bXVGIWuzA3iAmKc-1ud36Gi0UPCfSdmbEHfywH60HXBK7jgBwR0aWu5w-w\",\n" +
            "      \"e\": \"AQAB\",\n" +
            "      \"d\": \"eEoF1Ou2hShEK4UgXnumGdJZdLUx2DmbNgry0fP6LzmdkqGRoQ_U9z3DR-Cqv4IrKPlyjui9Tt75tjwMopEQViXHDRN6J7LiTmDL1HLFpDB2ZdpPoljx1A2j4yCMFMGjWhei2uZobXTXyGAN-qT06WZxHu9aF9as-uBbLpTkxSzefHk4nUn7xQAzjr-Ab9Bf-kSTN5_DaMGRayhYBj7taBfaNTTOTmNgTPMrK4PK9PPsqj9peI8kRLjqmoGC481e0YQL3M8j8-jpJ4KOyf1-ltqtcBUvl5rzOXtCRm-nopvg0iiQicwYhiIVHjCPGyUFu3SEHTtrOx2jYgt1X-wQYQ\",\n" +
            "      \"p\": \"69YuyA2FD8ZtyPUVmQsWM1v7O21ENQHt76VWbSKONQRMDSSqbwTwNpOM43ZOO1UY0iuaTCPIpjSqEUq9Zeshzdk5EnmD8Bctwzju-1Mb0964i1A2G9sp2JuGfUMNGo2in48WgA9BC5X2wTBLwTtHJMp2HJWDF3GS37UMJhOE2gs\",\n" +
            "      \"q\": \"laOL3EChEHKZWSU_q8v7dxRQcYX3n1JTfCZxJbopio_jTtQ0j5JDjsci0_emix7uXT3gQEtqEiAVZ5kE866nFJXEXdlYGdYD5Fv8geO8oc7PGnts1LfWQ5kpBGmdfsnGToqdDz21aW5ZLlTn0bIcpIq-QH1-bCvDc0w70v1cCtE\",\n" +
            "      \"dp\": \"qMgdrPD4FOUnNxYoAeLMXa9rqwk1MlaSKduDchG0Ar9zikh-bXv0SqrovvWxYYcyf1_TSsClXkX8nOmHiQRxqffXf6BVy6NbDgeWCWpeVRBltNaQEvmUBkCwTL-LBkDtbRIjwTypiZgnA_YDkWRSM0NuqmBadJHE0rOo4StA_ic\",\n" +
            "      \"dq\": \"Cwhj53lcZroMVGZKq3_-qmj1BWm7OCP5w82RyhZPuceiGs3KkktWb9B-4OIBhYBiUr2dKyBkUbHL4jeGBfF6oCnqsIC13jHJV6zwkSMZZVS6MFmpTIXBZnqEa67dzdtSo7fUnKsQFRXtvVzFOtDHC9qu7FJUX-VaI8YbIxNLFgE\",\n" +
            "      \"qi\": \"0shcudMZNYYqZyqUmzewV-CWQZ3-ZGv7Ba323bytigATnRRGx6w7QDB-JILxCTlHpU3zNDcuE-kGKWZIvQiZEmXjSsUOlzQsv-QB5ZIM44RNP8KScYSt1X8ud1GlOT9th4tUNYjqV1XBLZ-IjD3ogxoiaSZ1u_GSoN2CWnpH1Xg\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);
        List<JsonWebKey> jwks = jsonWebKeySet.getJsonWebKeys();

        DecryptionJwkSelector selector = new DecryptionJwkSelector();

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        jwe.setKeyIdHeaderValue("U-DESNk");
        List<JsonWebKey> selectedList = selector.selectList(jwe, jwks);
        assertThat(1, equalTo(selectedList.size()));
        JsonWebKey selected = selector.select(jwe, jwks);
        assertTrue(selected instanceof RsaJsonWebKey);

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
        jwe.setKeyIdHeaderValue("U-DESNk");
        selectedList = selector.selectList(jwe, jwks);
        assertThat(1, equalTo(selectedList.size()));
        selected = selectedList.iterator().next();
        assertTrue(selected instanceof RsaJsonWebKey);


        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
        jwe.setKeyIdHeaderValue("y-d_6-Q"); // kid for an ec key
        selectedList = selector.selectList(jwe, jwks);
        assertTrue(selectedList.isEmpty());

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        jwe.setKeyIdHeaderValue("rSK-0_k");
        selectedList = selector.selectList(jwe, jwks);
        assertThat(1, equalTo(selectedList.size()));
        selected = selectedList.iterator().next();
        assertTrue(selected instanceof EllipticCurveJsonWebKey);


        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jwe.setKeyIdHeaderValue("y-d_6-Q");
        selectedList = selector.selectList(jwe, jwks);
        assertThat(1, equalTo(selectedList.size()));
        selected = selectedList.iterator().next();
        assertTrue(selected instanceof EllipticCurveJsonWebKey);

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        jwe.setKeyIdHeaderValue("__8lh94"); // kid for an rsa key
        selectedList = selector.selectList(jwe, jwks);
        assertTrue(selectedList.isEmpty());
    }
}
