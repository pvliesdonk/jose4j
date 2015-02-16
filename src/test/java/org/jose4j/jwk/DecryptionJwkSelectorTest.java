package org.jose4j.jwk;


import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;

import org.junit.Test;

import java.util.List;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

/**
 *
 */
public class DecryptionJwkSelectorTest
{
    @Test
    public void someX5Selections() throws Exception
    {
        String json =
            "{\n" +
            "  \"keys\": [\n" +
            "    {\n" +
            "      \"kty\": \"RSA\",\n" +
            "      \"n\": \"v5UvsMi60ASbQEIKdOdkXDfBRKgoLHH4lZLwUiiDq_VscTatbZDvTFnfmFKHExTzn0LKTjTNhKhY81CNLTNItRqmsTZ5cMnR0PTS777ncQ70l_YxAXxpBWANOkEPzRMbF4R7d9GBJQUzKgVVWvGH_6BG-oSuDMc82j3rInMp38T-afcf3F9gcpfhELM1xChfjaMyExLezhPi2F4O41z9kWpHF3hYwu-h_xuJA_apc2gPf1RvpB6v2m4ll4QdnQIu1MIb_8z7018OWdCIUf2sGVepnHosiNxfdhmu9brwXSbYcbWVJUdmhB5bZze3af5nI4qtX_BV_YPgsfsczAKmuQ\",\n" +
            "      \"e\": \"AQAB\",\n" +
            "      \"x5c\": [\n" +
            "        \"MIIDKDCCAhCgAwIBAgIGAUqtA+agMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxFzAVBgNVBAMTDkJyaWFuIENhbXBiZWxsMB4XDTE1MDEwMjIzMzg0MVoXDTQyMDgyNDIyMzg0MVowVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC\\/lS+wyLrQBJtAQgp052RcN8FEqCgscfiVkvBSKIOr9WxxNq1tkO9MWd+YUocTFPOfQspONM2EqFjzUI0tM0i1GqaxNnlwydHQ9NLvvudxDvSX9jEBfGkFYA06QQ\\/NExsXhHt30YElBTMqBVVa8Yf\\/oEb6hK4MxzzaPesicynfxP5p9x\\/cX2Byl+EQszXEKF+NozITEt7OE+LYXg7jXP2RakcXeFjC76H\\/G4kD9qlzaA9\\/VG+kHq\\/abiWXhB2dAi7Uwhv\\/zPvTXw5Z0IhR\\/awZV6mceiyI3F92Ga71uvBdJthxtZUlR2aEHltnN7dp\\/mcjiq1f8FX9g+Cx+xzMAqa5AgMBAAEwDQYJKoZIhvcNAQELBQADggEBABwJ7Iw904nf4KiTviWa3j3OWauSOV0GpM\\/ORJbsIvqUada5VubOrN0+NRQJm3\\/TTFOIsvRqL86cpFf7ikpdfLjyKR\\/ZQVrop9yoCPQAiLe7IcPozngaLoHOK2OcEWRDbxPfBnhmxfyGqMxtXuqVIEIQ40AIjdimHgbTbmaMQIZpANgHryfJDrQJX2UXnqgtCYaJzoLJMFY7BrlO8mCSez8V886DpbTzXYJwDk4GCDYUTEvNUbFVvpVoWaYX2JtwP1fm+lQtiKhHyp1PCJh\\/5Ijbf6sTlONXWVSreWw6LKjixM\\/HNJnK5Yd3vSql\\/nwI3Cy2kGgzjCzUfcyQ\\/LU+2tI=\"\n" +
            "      ],\n" +
            "      \"d\": \"Df2lF_HwwpQzikPIY7UqPRnNQWhOVsCT-MhcSIOw6fPoUXQ-wgudjiPaElOkjZ4wFGdaQs_UWmW46Tvus2hVXPRvS-3AfJ4gdnQKm3uDh1wiPJ68AXHGcaAMFz79GmrUxajlI2DnX367t8vf6d5NojtgM5dQ5pn-Nanj7AYg_rhRjGjK783PepBCAHQ2zwdGBHaS_1e4IErtyCFiJN405O6_jacmdIEPATSNNItnrGVTDQjCI0hswVqXeOr2pUEDLWuXEcKS-0xZ4T1MV1MDipoNy4EtxHrQrXd32aY7IIp3QMWAgxeES24dSZRhdFICFPEhNb_jq88bpaGR6sbLAQ\",\n" +
            "      \"p\": \"-oaNOH47V97ZhC-YkPIpmVXVWVLmna1_dy_eBGpMqgITVyYJIBEY7S6BSEhm9bTLayCL_tePv3bgzzzusE2sAVcc-0ifoE2tFMi3gpk9130xEjQwDmFXcddCfjKbqf4nJWrmfTqAGIOu2A4JGozqcLRJdxbtDpP9X8Nk5vN52jE\",\n" +
            "      \"q\": \"w8ToEQ64_Hfxd-gnMyR4rI6jnnOlD884M3APYK8tHcux19n37zgEF29h9cn4h5Kyfs0x90ThGLtPPthCphqdS6K5v50X7A6p43GwojK9Ut2JT8FZxo6dlBBxtElE481sL832f_nBBpik9stz_JJvg89BvSNnjIldBmbfaG2f6wk\",\n" +
            "      \"dp\": \"N-7iiMJmLXAr0D9wKKxobTukrpS7uGiMFOgzAXlaNHrSJprvXqFyl0HSy3iexCzhXcGef_9QsMax2pMYF3S_-mygo9nLCddN1V4a2qWsEPh6hD3ynMNO6rPMvLA_4OxFgS0k2MC-6Lo9xy8bCTp8_TzDSjtsId0YrNDLLmUdx4E\",\n" +
            "      \"dq\": \"Vyc6CR38zKi5HyCDEwmRj4CQ5uGlAjzGUF_6-JgEBdfA_M9UyXKun6A-hCW-NtzgCgNf0y0e6Nu6k8fDJB-FFz8CYoOVOsnsaA0dDZh5IILvtknlpben_1qyxAg6WxAAseeHbcHKZR1fk19P64lli9Cg-4rfdnlQqKDzpJHpN8E\",\n" +
            "      \"qi\": \"8OHKueEcRf0KpoWmowEI4IFZRTZoSxDNxFlA5J0E5nMtqKxOLVVKn_wOQsUK1u4UOn4ull7ZbbRMZRhOLnVyggpHgJ7BN9hmiYUgN7qJx9PxSz0AZTUpX-FIP5V4p30tspPvfCHsbvZ2Sq-sB6BaPzV33W1X-Uc2kfl4EOsV-nA\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"RSA\",\n" +
            "      \"n\": \"neaZ2O9Auht0ZASyP4wr_kTkIis1QQkFXTD-gW9sXJQhYb6sISSGt_uu5lPZTcbLfIyROLgjWLcG7lPQ6dxbKtcU51wiFWLYu4Qjvk7zD17YJQD8xH0j5dzyo7zJqLbJjY3a32_V9K6r3O-MpGObH7BFs_PokvQkNHYIgwQR2KJfH_LDihRBcNV4pjrRa2qyeEjH5-wd21AqJdPgKnW-o92xGU-G71Qk6qOdjMDYnlXMEwvtxBssi22cgAlSAcW0p4pFUQWQUxahAND_LdACc-iGxLMxtvddJ9pxQxgBW8qQJratiwjCpYBVCB6Gw9uA76Ee65lF3fp8ldUt32mzCw\",\n" +
            "      \"e\": \"AQAB\",\n" +
            "      \"x5c\": [\n" +
            "        \"MIIDNDCCAhygAwIBAgIGAUqtD7sRMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxHTAbBgNVBAMTFEJyaWFuIERhdmlkIENhbXBiZWxsMB4XDTE1MDEwMjIzNTEzNloXDTQ1MDUyMDIyNTEzNlowWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCd5pnY70C6G3RkBLI\\/jCv+ROQiKzVBCQVdMP6Bb2xclCFhvqwhJIa3+67mU9lNxst8jJE4uCNYtwbuU9Dp3Fsq1xTnXCIVYti7hCO+TvMPXtglAPzEfSPl3PKjvMmotsmNjdrfb9X0rqvc74ykY5sfsEWz8+iS9CQ0dgiDBBHYol8f8sOKFEFw1XimOtFrarJ4SMfn7B3bUCol0+Aqdb6j3bEZT4bvVCTqo52MwNieVcwTC+3EGyyLbZyACVIBxbSnikVRBZBTFqEA0P8t0AJz6IbEszG2910n2nFDGAFbypAmtq2LCMKlgFUIHobD24DvoR7rmUXd+nyV1S3fabMLAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI94fDaieGwkj1dDSEM+2TJwrciMGdUM8EgMeWsVQgTS+xfkmvP5fjYW78eQ8072lYfkodsyC00hsUl8LFzsVKbAgU\\/+GQCVwd++JdguC8g3186cp2l6WxPHYFkCJs3QGEnarMIeD42dBjIB2HueOJ5rDKz6sC2g2c2lC7rTs662HPztPY9dRYLxWmy47C4YdPcn8toNatQjkC3j+w3K5QWZe5tf1X6C0xClmss8WyI+qJV13aPjHu8ybYJec5jryzKr9qT\\/t2YOzrvszkNTrUNFz4JCD9LXM0Vl5gdp6QOBSzwzhMeZcGJCQRuJa8fo\\/sCsoZFNzuNtmc5N2b5jxXQ=\"\n" +
            "      ],\n" +
            "      \"d\": \"lOH0OioNW-27JvuOnoCqkouel-Epy3KYDjC-KIlJIVnCyAki__US2bOETETPZpiFEaDw5Qwqt-GLtXhuSbOueoxmd2fV81hKhzSnBzAl2l5Ra0KtEw_zoy9b0auWcXA4RzJ0J62pjZaNEjsE35PTlmN8tZrLtpRg9t48VFyn_xxLMNth3SDn36jVpeCI5KZEitwaVzi5nnYONfpLT9v_iD8GRu1zUKeuXMbMbEcQW8WaoPQmPgrqaf7YD8apfS_6o5VQhl4SnY6mDnd1DnU3XnVS3JgNV5CKUZek1Tb27b6Z1YVpowgWcBQqXZz21pNVgDUrh8opLGZ1aFFgTBz38Q\",\n" +
            "      \"p\": \"6YkQv0LJKfnnot6uF5zFXkNn1q72rU_JwZnRCGqCHSpUltgiqysz0FchtmNnHcfgpd04UZe-hgwIf1L8xB3DthcDD3EEWhW8-Bmmz0xBvoWDXE4JR9eOlXCu9aBGjDY11uShK_pshB4EefESBaWv-z8t5S4_2KzRPSk8SOYgom8\",\n" +
            "      \"q\": \"rRb-Czx8WGm6JwRMhp0o0P3Af8ummUWnalhB11F9sjXsPM5DcakNmcir2RRwlk-1ixGIUFv7kxBrucNJ6YFNwBOQpbT94qGZxnpaI0MxKS2rXT8MCkVdMGdHwopig03POMGglVL9023QAsEMEldjvVqRL_VrUcXOY4NWhBep1yU\",\n" +
            "      \"dp\": \"MRQyJc_WUPEJIixkL-gtfmLyFqcMhl3HS92UlY00rQZxYoYnuwtIR1eYaSk4yYRxDMqSBGu8iZVLz95T6q9KqyDo7rzUqk35ObbCXLxs8KpEcgigYK3HdFaLHmnBicP2yqOfz4tAdP-N90aXgAJTGp0reweeOV4QVycsWTGr2Bc\",\n" +
            "      \"dq\": \"g8Gvyh_Vy3tXr2GPWx0At-2g_eaov52M7d-W5u9qTiDL3hFot3lnF_vwDEOJ3HF6kQzchccu_miOiA5HEg9Sfvalse3PIRfANZxnRtZb8quH-WgHoz3fzPuhXU335VlydxK1SVWuT6YUpDQNG10YWEg7opUfh1SaYZfVYKGesF0\",\n" +
            "      \"qi\": \"trOstogJZcLF2riK524vNERG0C3a_eGgKWgCkkr1o5rrx87hXEZC-eOrf2rtgZxTvK9RHvok2UVHuJBJUx7sVeMEo7NeKppUz16Tx9ie9WBrRGVvaBSUcPiaGytX_HuyMgOg7qeVki9GpFw7P1hFOLR-3wC4CeMTtJrf_J6r-WE\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"RSA\",\n" +
            "      \"n\": \"7LnNihjvihRLAHlwPC4rTAI-ToPNspm-QV9UTrNSYTdL_DePpuvWqis8iqOnWNzjTTQgBj__D6fjz7gdKnsdUtHT0H70inY92kU96MJaiIQol9ZxrGfjIumejOcbEkAmmfrMKPASl4US_NpcPYMtFzjJ3txNm6cgAVzYdZEmtW1vVa86etICUDQ_eD3bpHY4vcWB7m8slnnZ4JFbojDsfJUhTEuHzr_rkXI6XVrdv8kPnbEBK7dfbZVlcguQ1nFCiIUY4MO8f-zF7rF3d3AvqtxmQqNT_L1a67O0aoPldNmFJ0nl2hKywKwhx52fMT8VUqAT_W-aY-Ody-H8GWZBqw\",\n" +
            "      \"e\": \"AQAB\",\n" +
            "      \"x5c\": [\n" +
            "        \"MIIDLjCCAhagAwIBAgIGAUqtEXLzMA0GCSqGSIb3DQEBCwUAMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMQ8wDQYDVQQKEwZqb3NlNGoxGjAYBgNVBAMTEUJyaWFuIEQuIENhbXBiZWxsMB4XDTE1MDEwMjIzNTMyOVoXDTQzMDYyMDIyNTMyOVowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEaMBgGA1UEAxMRQnJpYW4gRC4gQ2FtcGJlbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDsuc2KGO+KFEsAeXA8LitMAj5Og82ymb5BX1ROs1JhN0v8N4+m69aqKzyKo6dY3ONNNCAGP\\/8Pp+PPuB0qex1S0dPQfvSKdj3aRT3owlqIhCiX1nGsZ+Mi6Z6M5xsSQCaZ+swo8BKXhRL82lw9gy0XOMne3E2bpyABXNh1kSa1bW9Vrzp60gJQND94Pdukdji9xYHubyyWedngkVuiMOx8lSFMS4fOv+uRcjpdWt2\\/yQ+dsQErt19tlWVyC5DWcUKIhRjgw7x\\/7MXusXd3cC+q3GZCo1P8vVrrs7Rqg+V02YUnSeXaErLArCHHnZ8xPxVSoBP9b5pj453L4fwZZkGrAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEL302pFrgsVDleaME1BvtTmZvE9ffBpiOc8k6kUpg30\\/I\\/ptXVHbMXcCLckn8OEclp8yf\\/8KgD0tZ5Sb501ucfYKWOKR1WBR1QunnLgzKiNflnZzITrXWI+cfwiJwn\\/PE2M5975dTDGeyzpGB6Tfn7HrfdLfoyMk5+rwehfG5\\/vX82fCZLM6NbxViaXJSud9hCVbxJEvvTUlVmVOrWhuebBJbtut4+RfI0RMm3AwYmRqZmnmNV85HZ9J5li7CoPHE9UHxxR8R8GWnsjQuB5og50FpGTub7OkyFTCnYSAUxmZYk4Z1BN8zMOD+JKOa5kZINouifPiwtXjq4aL7YCBUc=\"\n" +
            "      ],\n" +
            "      \"d\": \"R8h75FF1abiHmcg5WXZimLThceuT14G5aJdguFC2PVaISx4KCILhYE6mGCBSIacxofqZb2u-i1_Mu_NHnNciaDfKdCHbQ5VhYiu2_zrYOydgK9LSO4ZxIOgYtP9rfRhI3E5p1EwgRyQKQvRwHhMF_FGzHUpOmlGOaftehCAUzdShLfZdNp93ohpqamal1uisx9dbGqI1vX5_mQpvoH2OGBIhlVbp5EKMqib724y3GLOrbYgJDM_Z1BRNNSy51oceXieV7GcX-oT2Xv3YZfsLyM8JSZJzIiSl6_bykvGSxRv3E25JrtHtX9GDpE0YdatXm030_o2TjWtIfBZPabE5mQ\",\n" +
            "      \"p\": \"964kN9rx7_aWNj3vYHEkD4f_ka-JRDQknBgIdkK6use7oe6WE0iyhJolNemJRwB_JpAQ9kBfYjoyqgv_22tTvDAqU75uTm8mhvsefPxur-khp4IuUfwhbvT7GfR45-fbpubf8ic0IZ-PM6tc3mAYV4KEOGk4proUTO1FHYK8Yx8\",\n" +
            "      \"q\": \"9K12LZkuTK80EE1e7Z9QuOMR_kl4UUWDaJUmGMxI6Dh5EZ60Ny2jja3-vAzBxknfxopQpQa4A77ePTCChHBEw5uCC7AZAmeIuU2qqb1XZd2_7CBkJjsyxEr09eXDzy4sEqME9Ql6kCC6XZQ2LikmQuLvS7VddEMrdez90wiU-_U\",\n" +
            "      \"dp\": \"NJWaRumLGCFIPvfjTJx4xXtgPTQBdqODakiH82OzdVhWc8jNwAZdMF3xrIKKjLKETFGl6EI-fgJRI10s0w70Vi37ro_tp2VdzqaeEHcfoOVkKcYvw2Q-TOpiLV6EFOha8BJwVV8RaFoR8yxcqTHJuTqSi897IZq8GKD_XYaWLI0\",\n" +
            "      \"dq\": \"LOygczTZ5zGiS1Z9vG5AR4TCIADl7JujtfMlNymXPyRt9VzfdfPgbPItC50IsXfz4YlrI_dPi-4UTBwceH7UBWyz1TrIRlXhvCR7yg-Ho5yI09-TmnoJmCtZ8bZ23OxYOL4nRAjCwWUA5F6971zPk-4jxSORO-WbP1wIhhJrhx_U\",\n" +
            "      \"qi\": \"F7hzNEUauVSoyi9xSmp7uHSIHE3BiPMq-__Z1fZ7oODk3kmJeFzw3Jx5g8NaHsixA7DPb-aQ2Y_XPZPL28EuJqz2bbGguK9pAvwhqAPTZoNjWpJe5Ds5hL5dvGIxvvSLlZdgQmxzfsU_e1LtE5vae1kd5RxZgjcZ5Ssn9rBJBlQ\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"x\": \"bhH1zISTvaqIluqvQHcVXNVkf-oJlo3MXI34TvPpn0Y\",\n" +
            "      \"y\": \"a2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQ\",\n" +
            "      \"crv\": \"P-256\",\n" +
            "      \"x5c\": [\n" +
            "        \"MIIBoDCCAUSgAwIBAgIGAUqv7HETMAwGCCqGSM49BAMCBQAwVTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEXMBUGA1UEAxMOQnJpYW4gQ2FtcGJlbGwwHhcNMTUwMTAzMTMxMTU1WhcNNDMwNjIxMTIxMTU1WjBVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEPMA0GA1UEChMGam9zZTRqMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG4R9cyEk72qiJbqr0B3FVzVZH\\/qCZaNzFyN+E7z6Z9Ga2oX03bfUpSd8IOwnZja1NIdyITxWuFiBjnJV9pRPbQwDAYIKoZIzj0EAwIFAANIADBFAiEA7s85afZ5+ROkthajh87xg89spz8lzDmGolzPfbuPULwCICZC1q3Xyk70KKpZWpXaSlu0bfMkuNwG7RtMPv+ao+zb\"\n" +
            "      ],\n" +
            "      \"d\": \"81bMjwCNiMA8ZVRGSXkf9nSGvZ-uWTcFTZCu3S8TvAw\"\n" +
            "    },\n" +
            "    {\n" +
            "      \"kty\": \"EC\",\n" +
            "      \"x\": \"3CpPM7n0EwqENMDNKuDMkx5nNZ7F9xQKJ1FJ7XQY7Os\",\n" +
            "      \"y\": \"_B-nBJwT7Qsdv3RpAIZY-1NaZgzE-Mdu_CsWJ7LBDxk\",\n" +
            "      \"crv\": \"P-256\",\n" +
            "      \"x5c\": [\n" +
            "        \"MIIBqjCCAVCgAwIBAgIGAUqv7n85MAwGCCqGSM49BAMCBQAwWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNPMQ8wDQYDVQQHEwZEZW52ZXIxDzANBgNVBAoTBmpvc2U0ajEdMBsGA1UEAxMUQnJpYW4gRGF2aWQgQ2FtcGJlbGwwHhcNMTUwMTAzMTMxNDEwWhcNNDgwMjEyMTMxNDEwWjBbMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ08xDzANBgNVBAcTBkRlbnZlcjEPMA0GA1UEChMGam9zZTRqMR0wGwYDVQQDExRCcmlhbiBEYXZpZCBDYW1wYmVsbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNwqTzO59BMKhDTAzSrgzJMeZzWexfcUCidRSe10GOzr\\/B+nBJwT7Qsdv3RpAIZY+1NaZgzE+Mdu\\/CsWJ7LBDxkwDAYIKoZIzj0EAwIFAANGADBDAh8N9cKJYRq8kMmbpoqaB6PT\\/uVPK++RxBy5SWqCl0y1AiAQJfMfQJxZBZ0iCNYcpFmTpXIPaVxu50XHqafQETYQBg==\"\n" +
            "      ],\n" +
            "      \"d\": \"LzVM5880beqKgVOnrab4PCNiIEpaUa8niRaOsZY0apc\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        JsonWebKeySet jwks = new JsonWebKeySet(json);

        List<JsonWebKey> jsonWebKeys = jwks.getJsonWebKeys();

        DecryptionJwkSelector selector = new DecryptionJwkSelector();
        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setX509CertSha1ThumbprintHeaderValue("Zb1HT7ryCRAAj2wcQ8hWbzaqX1s");
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP);
        List<JsonWebKey> selectedList = selector.selectList(jwe, jsonWebKeys);
        assertThat(1, equalTo(selectedList.size()));
        JsonWebKey selected = selectedList.iterator().next();
        assertTrue(selected instanceof RsaJsonWebKey);

        jwe = new JsonWebEncryption();
        jwe.setX509CertSha1ThumbprintHeaderValue("W8aO-BD2jx9KMzQjhZ85ukJA5Zg");
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
        selectedList = selector.selectList(jwe, jsonWebKeys);
        assertThat(1, equalTo(selectedList.size()));
        selected = selectedList.iterator().next();
        assertTrue(selected instanceof EllipticCurveJsonWebKey);

        jwe = new JsonWebEncryption();
        jwe.setX509CertSha256ThumbprintHeaderValue("CJy-lAE3X0ar44cKrxKcauUHApD_ktFjPC9s6HeOxzU");
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
        selectedList = selector.selectList(jwe, jsonWebKeys);
        assertThat(1, equalTo(selectedList.size()));
        selected = selectedList.iterator().next();
        assertTrue(selected instanceof RsaJsonWebKey);
    }


    @Test
    public void someKidSelections() throws Exception
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

    @Test
    public void someKidSymmetricSelections() throws Exception
    {
        String json = "{\"keys\":[" +
                "{\"kty\":\"oct\",\"kid\":\"one\", \"k\":\"1gfpc39Jq5H5eR_JbwmAojgUlHIH0GoKz7COzLY1nRE\"}," +
                "{\"kty\":\"oct\",\"kid\":\"deux\",\"k\":\"9vlp7BLzRr-a9pOKK7BA25o88u6cY2o9Lz6--FfSWXw\"}," +
                "{\"kty\":\"oct\",\"kid\":\"tres\",\"k\":\"i001zDJd6-7rP5pnldgK-jcDjT8N12o3bIjwgeWAYEc\"}," +
                "{\"kty\":\"oct\",\"kid\":\"quatro\",\"k\":\"_-cqzgJ-_aeZkppR2JCOlx\"}," +
                "{\"kty\":\"oct\",\"kid\":\"cinque\",\"k\":\"FFsrZpj_Fbeal88Rz0c2Lk\"}," +
                "{\"kty\":\"oct\",\"kid\":\"sechs\", \"k\":\"ad2-dGiAp8czx9310j4o70\"}]}";

        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(json);
        List<JsonWebKey> jwks = jsonWebKeySet.getJsonWebKeys();

        DecryptionJwkSelector selector = new DecryptionJwkSelector();

        JsonWebEncryption jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
        jwe.setKeyIdHeaderValue("tres");
        List<JsonWebKey> selectedList = selector.selectList(jwe, jwks);
        assertThat(1, equalTo(selectedList.size()));
        JsonWebKey selected = selector.select(jwe, jwks);
        assertThat("tres", equalTo(selected.getKeyId()));

        jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.A128KW);
        jwe.setKeyIdHeaderValue("quatro");
        selectedList = selector.selectList(jwe, jwks);
        assertThat(1, equalTo(selectedList.size()));
        selected = selector.select(jwe, jwks);
        assertThat("quatro", equalTo(selected.getKeyId()));
    }
}
