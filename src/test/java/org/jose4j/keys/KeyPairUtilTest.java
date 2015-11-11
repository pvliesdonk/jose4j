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

package org.jose4j.keys;

import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;

import static org.hamcrest.CoreMatchers.*;

/**
 *
 */
public class KeyPairUtilTest
{
    @Test
    public void rsaPublicKeyEncodingDecodingAndSign() throws Exception
    {
        PublicJsonWebKey publicJsonWebKey = ExampleRsaJwksFromJwe.APPENDIX_A_1;
        String pem = KeyPairUtil.pemEncode(publicJsonWebKey.getPublicKey());
        String expectedPem = "-----BEGIN PUBLIC KEY-----\r\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoahUIoWw0K0usKNuOR6H\r\n" +
                "4wkf4oBUXHTxRvgb48E+BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINX\r\n" +
                "tqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk/ZkoFnilakGygTwpZ3uesH+PFABNI\r\n" +
                "UYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h+\r\n" +
                "QChLOln0/mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC+FCMfra36C9knD\r\n" +
                "FGzKsNa7LZK2djYgyD3JR/MB/4NUJW/TqOQtwHYbxevoJArm+L5StowjzGy+/bq6\r\n" +
                "GwIDAQAB\r\n" +
                "-----END PUBLIC KEY-----";
        Assert.assertThat(pem, equalTo(expectedPem));


        RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
        PublicKey publicKey = rsaKeyUtil.fromPemEncoded(pem);
        Assert.assertThat(publicKey, equalTo(publicJsonWebKey.getPublicKey()));

        JwtClaims claims = new JwtClaims();
        claims.setSubject("meh");
        claims.setExpirationTimeMinutesInTheFuture(20);
        claims.setGeneratedJwtId();
        claims.setAudience("you");
        claims.setIssuer("me");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(publicJsonWebKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        String jwt = jws.getCompactSerialization();

        Logger log = LoggerFactory.getLogger(this.getClass());
        log.debug("The following JWT and public key should be (and were on 11/11/15) usable and produce a valid " +
                "result at jwt.io (related to http://stackoverflow.com/questions/32744172):\n" + jwt + "\n" + pem);
    }

    @Test
    public void ecPublicKeyEncoding() throws Exception
    {
        PublicKey public256 = ExampleEcKeysFromJws.PUBLIC_256;
        String pemed = KeyPairUtil.pemEncode(public256);
        EcKeyUtil ecKeyUtil = new EcKeyUtil();
        PublicKey publicKey = ecKeyUtil.fromPemEncoded(pemed);
        Assert.assertThat(publicKey, equalTo(public256));
    }

}
