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

import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.X509Util;
import org.jose4j.keys.resolvers.X509VerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 *
 */
public class X509VerificationKeyResolverInJwtConsumerTest
{
    private static List<X509Certificate> CERT_LIST;

    @BeforeClass
    public static void initKeyList() throws JoseException
    {
        String j0 = "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"n\": \"v5UvsMi60ASbQEIKdOdkXDfBRKgoLHH4lZLwUiiDq_VscTatbZDvTFnfmFKHExTzn0LKTjTNhKhY81CNLTNItRqmsTZ5cMnR0PTS777ncQ70l_YxAXxpBWANOkEPzRMbF4R7d9GBJQUzKgVVWvGH_6BG-oSuDMc82j3rInMp38T-afcf3F9gcpfhELM1xChfjaMyExLezhPi2F4O41z9kWpHF3hYwu-h_xuJA_apc2gPf1RvpB6v2m4ll4QdnQIu1MIb_8z7018OWdCIUf2sGVepnHosiNxfdhmu9brwXSbYcbWVJUdmhB5bZze3af5nI4qtX_BV_YPgsfsczAKmuQ\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"x5c\": [\n" +
                "    \"MIIDKDCCAhCgAwIBAgIGAUqtA+agMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYT\\r\\nAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3Nl\\r\\nNGoxFzAVBgNVBAMTDkJyaWFuIENhbXBiZWxsMB4XDTE1MDEwMjIzMzg0MVoXDTQy\\r\\nMDgyNDIyMzg0MVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQH\\r\\nEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJl\\r\\nbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC\\/lS+wyLrQBJtAQgp0\\r\\n52RcN8FEqCgscfiVkvBSKIOr9WxxNq1tkO9MWd+YUocTFPOfQspONM2EqFjzUI0t\\r\\nM0i1GqaxNnlwydHQ9NLvvudxDvSX9jEBfGkFYA06QQ\\/NExsXhHt30YElBTMqBVVa\\r\\n8Yf\\/oEb6hK4MxzzaPesicynfxP5p9x\\/cX2Byl+EQszXEKF+NozITEt7OE+LYXg7j\\r\\nXP2RakcXeFjC76H\\/G4kD9qlzaA9\\/VG+kHq\\/abiWXhB2dAi7Uwhv\\/zPvTXw5Z0IhR\\r\\n\\/awZV6mceiyI3F92Ga71uvBdJthxtZUlR2aEHltnN7dp\\/mcjiq1f8FX9g+Cx+xzM\\r\\nAqa5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABwJ7Iw904nf4KiTviWa3j3OWauS\\r\\nOV0GpM\\/ORJbsIvqUada5VubOrN0+NRQJm3\\/TTFOIsvRqL86cpFf7ikpdfLjyKR\\/Z\\r\\nQVrop9yoCPQAiLe7IcPozngaLoHOK2OcEWRDbxPfBnhmxfyGqMxtXuqVIEIQ40AI\\r\\njdimHgbTbmaMQIZpANgHryfJDrQJX2UXnqgtCYaJzoLJMFY7BrlO8mCSez8V886D\\r\\npbTzXYJwDk4GCDYUTEvNUbFVvpVoWaYX2JtwP1fm+lQtiKhHyp1PCJh\\/5Ijbf6sT\\r\\nlONXWVSreWw6LKjixM\\/HNJnK5Yd3vSql\\/nwI3Cy2kGgzjCzUfcyQ\\/LU+2tI=\\r\\n\"\n" +
                "  ],\n" +
                "  \"d\": \"Df2lF_HwwpQzikPIY7UqPRnNQWhOVsCT-MhcSIOw6fPoUXQ-wgudjiPaElOkjZ4wFGdaQs_UWmW46Tvus2hVXPRvS-3AfJ4gdnQKm3uDh1wiPJ68AXHGcaAMFz79GmrUxajlI2DnX367t8vf6d5NojtgM5dQ5pn-Nanj7AYg_rhRjGjK783PepBCAHQ2zwdGBHaS_1e4IErtyCFiJN405O6_jacmdIEPATSNNItnrGVTDQjCI0hswVqXeOr2pUEDLWuXEcKS-0xZ4T1MV1MDipoNy4EtxHrQrXd32aY7IIp3QMWAgxeES24dSZRhdFICFPEhNb_jq88bpaGR6sbLAQ\",\n" +
                "  \"p\": \"-oaNOH47V97ZhC-YkPIpmVXVWVLmna1_dy_eBGpMqgITVyYJIBEY7S6BSEhm9bTLayCL_tePv3bgzzzusE2sAVcc-0ifoE2tFMi3gpk9130xEjQwDmFXcddCfjKbqf4nJWrmfTqAGIOu2A4JGozqcLRJdxbtDpP9X8Nk5vN52jE\",\n" +
                "  \"q\": \"w8ToEQ64_Hfxd-gnMyR4rI6jnnOlD884M3APYK8tHcux19n37zgEF29h9cn4h5Kyfs0x90ThGLtPPthCphqdS6K5v50X7A6p43GwojK9Ut2JT8FZxo6dlBBxtElE481sL832f_nBBpik9stz_JJvg89BvSNnjIldBmbfaG2f6wk\",\n" +
                "  \"dp\": \"N-7iiMJmLXAr0D9wKKxobTukrpS7uGiMFOgzAXlaNHrSJprvXqFyl0HSy3iexCzhXcGef_9QsMax2pMYF3S_-mygo9nLCddN1V4a2qWsEPh6hD3ynMNO6rPMvLA_4OxFgS0k2MC-6Lo9xy8bCTp8_TzDSjtsId0YrNDLLmUdx4E\",\n" +
                "  \"dq\": \"Vyc6CR38zKi5HyCDEwmRj4CQ5uGlAjzGUF_6-JgEBdfA_M9UyXKun6A-hCW-NtzgCgNf0y0e6Nu6k8fDJB-FFz8CYoOVOsnsaA0dDZh5IILvtknlpben_1qyxAg6WxAAseeHbcHKZR1fk19P64lli9Cg-4rfdnlQqKDzpJHpN8E\",\n" +
                "  \"qi\": \"8OHKueEcRf0KpoWmowEI4IFZRTZoSxDNxFlA5J0E5nMtqKxOLVVKn_wOQsUK1u4UOn4ull7ZbbRMZRhOLnVyggpHgJ7BN9hmiYUgN7qJx9PxSz0AZTUpX-FIP5V4p30tspPvfCHsbvZ2Sq-sB6BaPzV33W1X-Uc2kfl4EOsV-nA\"\n" +
                "}";

        String j1 = "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"n\": \"neaZ2O9Auht0ZASyP4wr_kTkIis1QQkFXTD-gW9sXJQhYb6sISSGt_uu5lPZTcbLfIyROLgjWLcG7lPQ6dxbKtcU51wiFWLYu4Qjvk7zD17YJQD8xH0j5dzyo7zJqLbJjY3a32_V9K6r3O-MpGObH7BFs_PokvQkNHYIgwQR2KJfH_LDihRBcNV4pjrRa2qyeEjH5-wd21AqJdPgKnW-o92xGU-G71Qk6qOdjMDYnlXMEwvtxBssi22cgAlSAcW0p4pFUQWQUxahAND_LdACc-iGxLMxtvddJ9pxQxgBW8qQJratiwjCpYBVCB6Gw9uA76Ee65lF3fp8ldUt32mzCw\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"x5c\": [\n" +
                "    \"MIIDNDCCAhygAwIBAgIGAUqtD7sRMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYT\\r\\nAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3Nl\\r\\nNGoxHTAbBgNVBAMTFEJyaWFuIERhdmlkIENhbXBiZWxsMB4XDTE1MDEwMjIzNTEz\\r\\nNloXDTQ1MDUyMDIyNTEzNlowWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8w\\r\\nDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEdMBsGA1UEAxMUQnJpYW4g\\r\\nRGF2aWQgQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCd\\r\\n5pnY70C6G3RkBLI\\/jCv+ROQiKzVBCQVdMP6Bb2xclCFhvqwhJIa3+67mU9lNxst8\\r\\njJE4uCNYtwbuU9Dp3Fsq1xTnXCIVYti7hCO+TvMPXtglAPzEfSPl3PKjvMmotsmN\\r\\njdrfb9X0rqvc74ykY5sfsEWz8+iS9CQ0dgiDBBHYol8f8sOKFEFw1XimOtFrarJ4\\r\\nSMfn7B3bUCol0+Aqdb6j3bEZT4bvVCTqo52MwNieVcwTC+3EGyyLbZyACVIBxbSn\\r\\nikVRBZBTFqEA0P8t0AJz6IbEszG2910n2nFDGAFbypAmtq2LCMKlgFUIHobD24Dv\\r\\noR7rmUXd+nyV1S3fabMLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI94fDaieGwk\\r\\nj1dDSEM+2TJwrciMGdUM8EgMeWsVQgTS+xfkmvP5fjYW78eQ8072lYfkodsyC00h\\r\\nsUl8LFzsVKbAgU\\/+GQCVwd++JdguC8g3186cp2l6WxPHYFkCJs3QGEnarMIeD42d\\r\\nBjIB2HueOJ5rDKz6sC2g2c2lC7rTs662HPztPY9dRYLxWmy47C4YdPcn8toNatQj\\r\\nkC3j+w3K5QWZe5tf1X6C0xClmss8WyI+qJV13aPjHu8ybYJec5jryzKr9qT\\/t2YO\\r\\nzrvszkNTrUNFz4JCD9LXM0Vl5gdp6QOBSzwzhMeZcGJCQRuJa8fo\\/sCsoZFNzuNt\\r\\nmc5N2b5jxXQ=\\r\\n\"\n" +
                "  ],\n" +
                "  \"d\": \"lOH0OioNW-27JvuOnoCqkouel-Epy3KYDjC-KIlJIVnCyAki__US2bOETETPZpiFEaDw5Qwqt-GLtXhuSbOueoxmd2fV81hKhzSnBzAl2l5Ra0KtEw_zoy9b0auWcXA4RzJ0J62pjZaNEjsE35PTlmN8tZrLtpRg9t48VFyn_xxLMNth3SDn36jVpeCI5KZEitwaVzi5nnYONfpLT9v_iD8GRu1zUKeuXMbMbEcQW8WaoPQmPgrqaf7YD8apfS_6o5VQhl4SnY6mDnd1DnU3XnVS3JgNV5CKUZek1Tb27b6Z1YVpowgWcBQqXZz21pNVgDUrh8opLGZ1aFFgTBz38Q\",\n" +
                "}";

        String j2 = "{\n" +
                "  \"kty\": \"RSA\",\n" +
                "  \"n\": \"7LnNihjvihRLAHlwPC4rTAI-ToPNspm-QV9UTrNSYTdL_DePpuvWqis8iqOnWNzjTTQgBj__D6fjz7gdKnsdUtHT0H70inY92kU96MJaiIQol9ZxrGfjIumejOcbEkAmmfrMKPASl4US_NpcPYMtFzjJ3txNm6cgAVzYdZEmtW1vVa86etICUDQ_eD3bpHY4vcWB7m8slnnZ4JFbojDsfJUhTEuHzr_rkXI6XVrdv8kPnbEBK7dfbZVlcguQ1nFCiIUY4MO8f-zF7rF3d3AvqtxmQqNT_L1a67O0aoPldNmFJ0nl2hKywKwhx52fMT8VUqAT_W-aY-Ody-H8GWZBqw\",\n" +
                "  \"e\": \"AQAB\",\n" +
                "  \"x5c\": [\n" +
                "    \"MIIDLjCCAhagAwIBAgIGAUqtEXLzMA0GCSqGSIb3DQEBCwUAMFgxCzAJBgNVBAYT\\r\\nAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3Nl\\r\\nNGoxGjAYBgNVBAMTEUJyaWFuIEQuIENhbXBiZWxsMB4XDTE1MDEwMjIzNTMyOVoX\\r\\nDTQzMDYyMDIyNTMyOVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYD\\r\\nVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEaMBgGA1UEAxMRQnJpYW4gRC4g\\r\\nQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsuc2KGO+K\\r\\nFEsAeXA8LitMAj5Og82ymb5BX1ROs1JhN0v8N4+m69aqKzyKo6dY3ONNNCAGP\\/8P\\r\\np+PPuB0qex1S0dPQfvSKdj3aRT3owlqIhCiX1nGsZ+Mi6Z6M5xsSQCaZ+swo8BKX\\r\\nhRL82lw9gy0XOMne3E2bpyABXNh1kSa1bW9Vrzp60gJQND94Pdukdji9xYHubyyW\\r\\nedngkVuiMOx8lSFMS4fOv+uRcjpdWt2\\/yQ+dsQErt19tlWVyC5DWcUKIhRjgw7x\\/\\r\\n7MXusXd3cC+q3GZCo1P8vVrrs7Rqg+V02YUnSeXaErLArCHHnZ8xPxVSoBP9b5pj\\r\\n453L4fwZZkGrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEL302pFrgsVDleaME1B\\r\\nvtTmZvE9ffBpiOc8k6kUpg30\\/I\\/ptXVHbMXcCLckn8OEclp8yf\\/8KgD0tZ5Sb501\\r\\nucfYKWOKR1WBR1QunnLgzKiNflnZzITrXWI+cfwiJwn\\/PE2M5975dTDGeyzpGB6T\\r\\nfn7HrfdLfoyMk5+rwehfG5\\/vX82fCZLM6NbxViaXJSud9hCVbxJEvvTUlVmVOrWh\\r\\nuebBJbtut4+RfI0RMm3AwYmRqZmnmNV85HZ9J5li7CoPHE9UHxxR8R8GWnsjQuB5\\r\\nog50FpGTub7OkyFTCnYSAUxmZYk4Z1BN8zMOD+JKOa5kZINouifPiwtXjq4aL7YC\\r\\nBUc=\\r\\n\"\n" +
                "  ],\n" +
                "  \"d\": \"R8h75FF1abiHmcg5WXZimLThceuT14G5aJdguFC2PVaISx4KCILhYE6mGCBSIacxofqZb2u-i1_Mu_NHnNciaDfKdCHbQ5VhYiu2_zrYOydgK9LSO4ZxIOgYtP9rfRhI3E5p1EwgRyQKQvRwHhMF_FGzHUpOmlGOaftehCAUzdShLfZdNp93ohpqamal1uisx9dbGqI1vX5_mQpvoH2OGBIhlVbp5EKMqib724y3GLOrbYgJDM_Z1BRNNSy51oceXieV7GcX-oT2Xv3YZfsLyM8JSZJzIiSl6_bykvGSxRv3E25JrtHtX9GDpE0YdatXm030_o2TjWtIfBZPabE5mQ\",\n" +
                "  \"p\": \"964kN9rx7_aWNj3vYHEkD4f_ka-JRDQknBgIdkK6use7oe6WE0iyhJolNemJRwB_JpAQ9kBfYjoyqgv_22tTvDAqU75uTm8mhvsefPxur-khp4IuUfwhbvT7GfR45-fbpubf8ic0IZ-PM6tc3mAYV4KEOGk4proUTO1FHYK8Yx8\",\n" +
                "  \"q\": \"9K12LZkuTK80EE1e7Z9QuOMR_kl4UUWDaJUmGMxI6Dh5EZ60Ny2jja3-vAzBxknfxopQpQa4A77ePTCChHBEw5uCC7AZAmeIuU2qqb1XZd2_7CBkJjsyxEr09eXDzy4sEqME9Ql6kCC6XZQ2LikmQuLvS7VddEMrdez90wiU-_U\",\n" +
                "  \"dp\": \"NJWaRumLGCFIPvfjTJx4xXtgPTQBdqODakiH82OzdVhWc8jNwAZdMF3xrIKKjLKETFGl6EI-fgJRI10s0w70Vi37ro_tp2VdzqaeEHcfoOVkKcYvw2Q-TOpiLV6EFOha8BJwVV8RaFoR8yxcqTHJuTqSi897IZq8GKD_XYaWLI0\",\n" +
                "  \"dq\": \"LOygczTZ5zGiS1Z9vG5AR4TCIADl7JujtfMlNymXPyRt9VzfdfPgbPItC50IsXfz4YlrI_dPi-4UTBwceH7UBWyz1TrIRlXhvCR7yg-Ho5yI09-TmnoJmCtZ8bZ23OxYOL4nRAjCwWUA5F6971zPk-4jxSORO-WbP1wIhhJrhx_U\",\n" +
                "  \"qi\": \"F7hzNEUauVSoyi9xSmp7uHSIHE3BiPMq-__Z1fZ7oODk3kmJeFzw3Jx5g8NaHsixA7DPb-aQ2Y_XPZPL28EuJqz2bbGguK9pAvwhqAPTZoNjWpJe5Ds5hL5dvGIxvvSLlZdgQmxzfsU_e1LtE5vae1kd5RxZgjcZ5Ssn9rBJBlQ\"\n" +
                "}";

        String j3 = "{\n" +
                "  \"kty\": \"EC\",\n" +
                "  \"x\": \"bhH1zISTvaqIluqvQHcVXNVkf-oJlo3MXI34TvPpn0Y\",\n" +
                "  \"y\": \"a2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQ\",\n" +
                "  \"crv\": \"P-256\",\n" +
                "  \"x5c\": [\n" +
                "    \"MIIBoDCCAUSgAwIBAgIGAUqv7HETMAwGCCqGSM49BAMCBQAwVTELMAkGA1UEBhMC\\r\\nVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0\\r\\najEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJlbGwwHhcNMTUwMTAzMTMxMTU1WhcNNDMw\\r\\nNjIxMTIxMTU1WjBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcT\\r\\nBkRlbnZlcjEPMA0GA1UEChMGam9zZTRqMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVs\\r\\nbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG4R9cyEk72qiJbqr0B3FVzVZH\\/q\\r\\nCZaNzFyN+E7z6Z9Ga2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQwDAYI\\r\\nKoZIzj0EAwIFAANIADBFAiEA7s85afZ5+ROkthajh87xg89spz8lzDmGolzPfbuP\\r\\nULwCICZC1q3Xyk70KKpZWpXaSlu0bfMkuNwG7RtMPv+ao+zb\\r\\n\"\n" +
                "  ],\n" +
                "  \"d\": \"81bMjwCNiMA8ZVRGSXkf9nSGvZ-uWTcFTZCu3S8TvAw\"\n" +
                "}";

        String j4 = "{\n" +
                "  \"kty\": \"EC\",\n" +
                "  \"x\": \"3CpPM7n0EwqENMDNKuDMkx5nNZ7F9xQKJ1FJ7XQY7Os\",\n" +
                "  \"y\": \"_B-nBJwT7Qsdv3RpAIZY-1NaZgzE-Mdu_CsWJ7LBDxk\",\n" +
                "  \"crv\": \"P-256\",\n" +
                "  \"x5c\": [\n" +
                "    \"MIIBqjCCAVCgAwIBAgIGAUqv7n85MAwGCCqGSM49BAMCBQAwWzELMAkGA1UEBhMC\\r\\nVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0\\r\\najEdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJlbGwwHhcNMTUwMTAzMTMxNDEw\\r\\nWhcNNDgwMjEyMTMxNDEwWjBbMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzAN\\r\\nBgNVBAcTBkRlbnZlcjEPMA0GA1UEChMGam9zZTRqMR0wGwYDVQQDExRCcmlhbiBE\\r\\nYXZpZCBDYW1wYmVsbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNwqTzO59BMK\\r\\nhDTAzSrgzJMeZzWexfcUCidRSe10GOzr\\/B+nBJwT7Qsdv3RpAIZY+1NaZgzE+Mdu\\r\\n\\/CsWJ7LBDxkwDAYIKoZIzj0EAwIFAANGADBDAh8N9cKJYRq8kMmbpoqaB6PT\\/uVP\\r\\nK++RxBy5SWqCl0y1AiAQJfMfQJxZBZ0iCNYcpFmTpXIPaVxu50XHqafQETYQBg==\\r\\n\"\n" +
                "  ],\n" +
                "  \"d\": \"LzVM5880beqKgVOnrab4PCNiIEpaUa8niRaOsZY0apc\"\n" +
                "}";

        CERT_LIST = new ArrayList<>();
        for (String s : new String[] {j0, j1, j2, j3, j4})
        {
            PublicJsonWebKey publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk(s);
            CERT_LIST.add(publicJsonWebKey.getLeafCertificate());
        }
        CERT_LIST = Collections.unmodifiableList(CERT_LIST);
    }

    @Test
    public void x5tStuff() throws Exception
    {
        String jwt = "eyJ4NXQiOiJaYjFIVDdyeUNSQUFqMndjUThoV2J6YXFYMXMiLCJhbGciOiJSUzI1NiJ9." +
                "eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5NjI1Nywic3ViIjoiYWJvdXQifQ." +
                "RidDM9z0OJkfV2mwxABtEh2Gr_BCFbTuetOTV_dmnFofarBK7VDPPdsdAhtIs3u7WQq9guoo6H3AUGfj4mTFKX3axi2TsaYRKM9wSoRjx" +
                "FO7ednGcRGx8bnSerqqrbBuM9ZUUt93sIXuneJHYRKlh0Tt9mCXISv1H4OMEueXOJhck-JPgLPfLDqIPa8t93SULKTQtLvs8KEby2uJOL" +
                "8vIy-a-lFp9irCWwTnd0QRidpuLAPLr428LPNPycEVqD2TpY7y_xaQJh49oqoq_AmQCmIn3CpZLDLqD1wpEPxLQyd1vbvgQ583y2XJ95_" +
                "QufjbRd2Oshv3Z3JxpIm9Yie6yQ";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST))
                .setEvaluationTime(NumericDate.fromSeconds(1420296253))
                .setExpectedAudience("you")
                .build();

        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
        Assert.assertThat("about", CoreMatchers.equalTo(jwtClaims.getSubject()));
        jwtConsumer.processContext(jwtContext);
        Assert.assertThat("about", CoreMatchers.equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST.get(0), CERT_LIST.get(2), CERT_LIST.get(3), CERT_LIST.get(4)))
                .setEvaluationTime(NumericDate.fromSeconds(1420296253))
                .setExpectedAudience("you")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, jwtConsumer);
    }

    @Test
    public void x5tS256Stuff() throws Exception
    {
        String jwt = "eyJ4NXQjUzI1NiI6IkZTcU90QjV2UHFaNGtqWXAwOUZqQnBrbVhIMFZxRURtLXdFY1Rjb3g2RUUiLCJhbGciOiJFUzI1NiJ9." +
                "eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5OTUzOSwic3ViIjoiYWJvdXQifQ." +
                "9Nj3UG8N9u7Eyu0wupR-eVS4Mf0ItwwHBZzwLcY2KUCJeWoPRPT7zC4MqMbHfLj6PzFi09iC3q3PniSJwmWJTA";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST))
                .setEvaluationTime(NumericDate.fromSeconds(1420299538))
                .setExpectedAudience("you")
                .build();

        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
        Assert.assertThat("about", CoreMatchers.equalTo(jwtClaims.getSubject()));
        jwtConsumer.processContext(jwtContext);
        Assert.assertThat("about", CoreMatchers.equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST.get(0),CERT_LIST.get(1), CERT_LIST.get(2), CERT_LIST.get(3)))
                .setEvaluationTime(NumericDate.fromSeconds(1420299538))
                .setExpectedAudience("you")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, jwtConsumer);
    }

    @Test
    public void bothX5headersStuff() throws Exception
    {
        String jwt = "eyJ4NXQjUzI1NiI6InFTX2JYTlNfSklYQ3JuUmdha2I2b3RFS3Utd0xlb3R6N0tBWjN4UVVPcUUiLCJ4NXQiOiJpSFFLdVNHZVdVR1laQ2c0X1JHSlNJQzBORFEiLCJhbGciOiJFUzI1NiJ9." +
                "eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5OTc2MSwic3ViIjoiYWJvdXQifQ." +
                "04qPYooLJN2G0q0LYVepaydszTuhY7jKjqi5IGkNBAWZ-IBlW_pWzkurR1MkO48SbJQK2swmy7Ogfihi1ClAlA";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST))
                .setEvaluationTime(NumericDate.fromSeconds(1420299760))
                .setExpectedAudience("you")
                .build();

        JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
        Assert.assertThat("about", CoreMatchers.equalTo(jwtClaims.getSubject()));
        jwtConsumer.processContext(jwtContext);
        Assert.assertThat("about", CoreMatchers.equalTo(jwtContext.getJwtClaims().getSubject()));

        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST.get(0),CERT_LIST.get(1), CERT_LIST.get(2), CERT_LIST.get(4)))
                .setEvaluationTime(NumericDate.fromSeconds(1420299760))
                .setExpectedAudience("you")
                .build();

        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, jwtConsumer);
    }

    @Test
    public void noThumbHeader() throws InvalidJwtException, MalformedClaimException
    {
        // signed w/ 1
        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtZSIsImF1ZCI6InlvdSIsImV4cCI6MTQyMDI5ODk3OSwic3ViIjoiYWJvdXQifQ.HtKEtmJOb5mmhHni5iJ0FUAEoNStpPZuFmQh7dtw-A7gIYsIUgdLumKCMgjG4OX_hDjvoSGl1XvHwYuzM24AohOJAaSdhLBnxTLZ4NumVwGLWp1uSjSy6stwkZrA3c9qLohLvib3RuX_x20ziOfA6YOMWwaAG66u93VwgG2upXBPwnySUuQYSPbFbSCTacoyJ9jTFu8ggeuI57dH34TyNXJK1F1Kow5IRfsioyVHsT4mP4HRk6xLXOIclf3vsfPoAG9GR8jxpDYxKZXBrDqt8gnKefGcOe6lqQv1zS7Vrb6NO8ejVo5g5tkw5-Kbpu775ShB0-mHrMocrw1n8NmQlA";

        JwtConsumer firstPassConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();
        JwtContext jwtContext = firstPassConsumer.process(jwt);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(new X509VerificationKeyResolver(CERT_LIST.get(0), CERT_LIST.get(1)))
                .setEvaluationTime(NumericDate.fromSeconds(1420298972))
                .setExpectedAudience("you")
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, jwtConsumer);

        List<X509Certificate> certificates = new ArrayList<>(CERT_LIST);
        Collections.reverse(certificates);
        List<List<X509Certificate>> certificateListList = new ArrayList<>();
        certificateListList.add(certificates);
        certificateListList.add(Arrays.asList(CERT_LIST.get(2), CERT_LIST.get(1), CERT_LIST.get(0)));
        certificateListList.add(Arrays.asList(CERT_LIST.get(1), CERT_LIST.get(0)));
        certificateListList.add(Arrays.asList(CERT_LIST.get(0), CERT_LIST.get(1)));
        certificateListList.add(Arrays.asList(CERT_LIST.get(1)));
        certificateListList.add(Arrays.asList(CERT_LIST.get(3), CERT_LIST.get(1)));

        for (List<X509Certificate> certificateList : certificateListList)
        {
            X509VerificationKeyResolver verificationKeyResolver = new X509VerificationKeyResolver(certificateList);
            verificationKeyResolver.setTryAllOnNoThumbHeader(true);  // no x5 in header so this is needed for it to work
            jwtConsumer = new JwtConsumerBuilder()
                    .setVerificationKeyResolver(verificationKeyResolver)
                    .setEvaluationTime(NumericDate.fromSeconds(1420298972))
                    .setExpectedAudience("you")
                    .build();
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            Assert.assertThat("about", CoreMatchers.equalTo(jwtClaims.getSubject()));
            jwtConsumer.processContext(jwtContext);
            Assert.assertThat("about", CoreMatchers.equalTo(jwtContext.getJwtClaims().getSubject()));

        }

        X509VerificationKeyResolver verificationKeyResolver = new X509VerificationKeyResolver(CERT_LIST.get(0), CERT_LIST.get(2)); // but 1 was the signer
        verificationKeyResolver.setTryAllOnNoThumbHeader(true);
        jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKeyResolver(verificationKeyResolver)
                .setEvaluationTime(NumericDate.fromSeconds(1420298972))
                .setExpectedAudience("you")
                .build();
        SimpleJwtConsumerTestHelp.expectProcessingFailure(jwt, jwtContext, jwtConsumer);
    }

    @Test
    public void compareToOpenSslFingerprints() throws Exception
    {
        compareToOpenSslFingerprint("67:30:12:77:0B:B0:31:86:C4:19:57:79:04:FA:A2:79:FF:75:23:4B",
                "08:9C:BE:94:01:37:5F:46:AB:E3:87:0A:AF:12:9C:6A:E5:07:02:90:FF:92:D1:63:3C:2F:6C:E8:77:8E:C7:35",
                CERT_LIST.get(0));

        compareToOpenSslFingerprint("65:BD:47:4F:BA:F2:09:10:00:8F:6C:1C:43:C8:56:6F:36:AA:5F:5B",
                "15:20:16:EE:C7:99:83:CB:A2:42:BF:75:0D:CE:D6:18:23:95:E3:A0:BE:5C:E6:4E:C9:EF:1A:E6:07:51:36:46",
                CERT_LIST.get(1));

        compareToOpenSslFingerprint("0E:49:9C:40:CE:40:CC:3F:27:9D:03:95:E4:51:3F:63:5A:34:97:96",
                "6C:34:95:6E:9E:3D:D2:ED:EE:D7:DE:31:0A:15:FA:CD:76:FF:76:80:6F:9B:5F:CE:D4:F2:4C:F5:FC:5C:3A:20",
                CERT_LIST.get(2));

        compareToOpenSslFingerprint("88:74:0A:B9:21:9E:59:41:98:64:28:38:FD:11:89:48:80:B4:34:34",
                "A9:2F:DB:5C:D4:BF:24:85:C2:AE:74:60:6A:46:FA:A2:D1:0A:BB:EC:0B:7A:8B:73:EC:A0:19:DF:14:14:3A:A1",
                CERT_LIST.get(3));

        compareToOpenSslFingerprint("5B:C6:8E:F8:10:F6:8F:1F:4A:33:34:23:85:9F:39:BA:42:40:E5:98",
                "15:2A:8E:B4:1E:6F:3E:A6:78:92:36:29:D3:D1:63:06:99:26:5C:7D:15:A8:40:E6:FB:01:1C:4D:CA:31:E8:41",
                CERT_LIST.get(4));
    }

    void compareToOpenSslFingerprint(String sha1fp, String sha256fp, X509Certificate certificate)
    {
        sha1fp = sha1fp.replace(":", "");
        String x5t = X509Util.x5t(certificate);
        Assert.assertArrayEquals(Hex.decode(sha1fp), Base64Url.decode(x5t));

        sha256fp = sha256fp.replace(":", "");
        String x5tS2 = X509Util.x5tS256(certificate);
        Assert.assertArrayEquals(Hex.decode(sha256fp), Base64Url.decode(x5tS2));
    }
}
