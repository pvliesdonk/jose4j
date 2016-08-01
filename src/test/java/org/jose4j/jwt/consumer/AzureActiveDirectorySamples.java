package org.jose4j.jwt.consumer;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class AzureActiveDirectorySamples
{
    @Test
    public void consumeAzureIDTokenV1() throws Exception
    {
        // ID token issued from https://login.microsoftonline.com/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/oauth2/authorize?scope=openid&client_id=56c77428-2d91-48a0-93e6-ca9154965e51&response_type=code&redirect_uri=...etc
        String idToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9." +
                "eyJhdWQiOiI1NmM3NzQyOC0yZDkxLTQ4YTAtOTNlNi1jYTkxNTQ5NjVlNTEiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8zMGFhMGU1OC03MTljLTQ0ZjAtYjViYi1lMTMx" +
                "ZjFmNjhhYjMvIiwiaWF0IjoxNDcwMDg2OTk3LCJuYmYiOjE0NzAwODY5OTcsImV4cCI6MTQ3MDA5MDg5NywiYW1yIjpbInB3ZCJdLCJmYW1pbHlfbmFtZSI6IkNhbXBiZWxsIiwiZ2l2" +
                "ZW5fbmFtZSI6IkJyaWFuIiwiaXBhZGRyIjoiMjA1LjE2OS42OC4yMTgiLCJuYW1lIjoiQnJpYW4gQ2FtcGJlbGwiLCJvaWQiOiJmZDJkZGRlMy04Mjc1LTRiMjgtOTlkMy0wMWIwNmY3" +
                "MTg4NWEiLCJzdWIiOiJSNmZwYXZGcnpyWkY3VnVHM3c3RUNWREFJcmJmXzVPLVNCWTk4NkdwZ2FvIiwidGlkIjoiMzBhYTBlNTgtNzE5Yy00NGYwLWI1YmItZTEzMWYxZjY4YWIzIiwi" +
                "dW5pcXVlX25hbWUiOiJ4QGNib2lkY3Rlc3R0ZXN0dGVzdC5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJ4QGNib2lkY3Rlc3R0ZXN0dGVzdC5vbm1pY3Jvc29mdC5jb20iLCJ2ZXIiOiIx" +
                "LjAifQ." +
                "VWoMoC9Rx0DR394fQ9SKLv-6iUlADh9lcueJIYkH8jPuQhIMbvQJoUJ2TIg-ToFUJejgTRdI2BjokZa7FKtqT_7ZGfPwm9dvGCVsHPGkfvxwnvHMrLxbguqGZF941X1HmJ_2s" +
                "l39PK3wgvLv5Lp0mEtvsKxUTCwSR3xev1c5lF_XekEcJnKVW7zWKmUG25dy--hItIdyvrN09p8ibRW-jf4i8RPrFbduLpR-6nUyd7oBmqKynwQc1_rPU52T1cKQsykLJn9e77_0FewDv" +
                "B7ggb0gK6cf08MpNk6lfbwvtmpEJS77AgEYYg5LwxNrm7uiZBAai1QWOqtNzmEU5s5Mpg";

        // content from https://login.microsoftonline.com/common/discovery/keys on Aug 1, 2016
        String jwks = "{\"keys\":[" +
                "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"MnC_VZcATfM5pOYiJHMba9goEKY\",\"x5t\":\"MnC_VZcATfM5pOYiJHMba9goEKY\"," +
                "\"n\":\"vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq-RtwN1Vs_z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1" +
                "k3cR1RW_EW_P-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5yCw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2Kq6TSvRHJqxRR68Rez" +
                "Ytje9KAqwqx4jxlmVAQy0T3-T-IAbsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3" +
                "zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEA" +
                "xMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD3" +
                "9E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgs" +
                "OU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf" +
                "3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOK" +
                "RMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19" +
                "W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\"]}," +
                "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"YbRAQRYcE_motWVJKHrwLBbd_9s\",\"x5t\":\"YbRAQRYcE_motWVJKHrwLBbd_9s\"," +
                "\"n\":\"vbcFrj193Gm6zeo5e2_y54Jx49sIgScv-2JO-n6NxNqQaKVnMkHcz-S1j2FfpFngotwGMzZIKVCY1SK8SKZMFfRTU3wvToZITwf3W1Qq6n-h-abqpyJTaqIcfhA0d6kEAM5N" +
                "sQAKhfvw7fre1QicmU9LWVWUYAayLmiRX6o3tktJq6H58pUzTtx_D0Dprnx6z5sW-uiMipLXbrgYmOez7htokJVgDg8w-yDFCxZNo7KVueUkLkxhNjYGkGfnt18s7ZW036WoTmdaQmW4" +
                "CChf_o4TLE5VyGpYWm7I_-nV95BBvwlzokVVKzveKf3l5UU3c6PkGy-BB3E_ChqFm6sPWw\",\"e\":\"AQAB\",\"x5c\":[\"MIIC4jCCAcqgAwIBAgIQfQ29fkGSsb1J8n2KueDFt" +
                "DANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE2MDQxNzAwMDAwMFoXDTE4MDQxNzAwMDAwMFowLTErMCkGA1UEA" +
                "xMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL23Ba49fdxpus3qOXtv8ueCcePbCIEnL/tiTvp+jcTakGilZ" +
                "zJB3M/ktY9hX6RZ4KLcBjM2SClQmNUivEimTBX0U1N8L06GSE8H91tUKup/ofmm6qciU2qiHH4QNHepBADOTbEACoX78O363tUInJlPS1lVlGAGsi5okV+qN7ZLSauh+fKVM07cfw9A6" +
                "a58es+bFvrojIqS1264GJjns+4baJCVYA4PMPsgxQsWTaOylbnlJC5MYTY2BpBn57dfLO2VtN+lqE5nWkJluAgoX/6OEyxOVchqWFpuyP/p1feQQb8Jc6JFVSs73in95eVFN3Oj5Bsvg" +
                "QdxPwoahZurD1sCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAe5RxtMLU2i4/vN1YacncR3GkOlbRv82rll9cd5mtVmokAw7kwbFBFNo2vIVkun+n+VdJf+QRzmHGm3ABtKwz3DPr78y0q" +
                "dVFA3h9P60hd3wqu2k5/Q8s9j1Kq3u9TIEoHlGJqNzjqO7khX6VcJ6BRLzoefBYavqoDSgJ3mkkYCNqTV2ZxDNks3obPg4yUkh5flULH14TqlFIOhXbsd775aPuMT+/tyqcc6xohU5Ny" +
                "YA63KtWG1BLDuF4LEF84oNPcY9i0n6IphEGgz20H7YcLRNjU55pDbWGdjE4X8ANb23kAc75RZn9EY4qYCiqeIAg3qEVKLnLUx0fNKMHmuedjg==\"]}]}";

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedIssuer("https://sts.windows.net/30aa0e58-719c-44f0-b5bb-e131f1f68ab3/")
                .setExpectedAudience("56c77428-2d91-48a0-93e6-ca9154965e51")
                .setRequireSubject()
                .setExpectedSubject("R6fpavFrzrZF7VuG3w7ECVDAIrbf_5O-SBY986Gpgao")
                .setEvaluationTime(NumericDate.fromSeconds(1470086999))
                .setVerificationKeyResolver(new JwksVerificationKeyResolver(new JsonWebKeySet(jwks).getJsonWebKeys()))
                .build();

        JwtClaims jwtClaims = jwtConsumer.processToClaims(idToken);
        System.out.println(jwtClaims);

        assertThat("Brian Campbell", equalTo(jwtClaims.getStringClaimValue("name")));
        assertThat("1.0", equalTo(jwtClaims.getStringClaimValue("ver")));
    }
}
