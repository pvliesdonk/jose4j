package com.notsure;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.binary.Hex;
import org.jose4j.lang.ByteUtil;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.jose4j.keys.BigEndianBigInteger;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.math.BigInteger;

/**
 * Hello world!
 *
 */
public class App 
{
    private static final String DOT = ".";

    static String newline = new String(new char[]{0x0d, 0x0a});
    

    public static void main( String[] args ) throws Exception
    {

        BigInteger n = ExampleRsaKeyFromJws.PUBLIC_KEY.getModulus();
        String myHexing = Hex.encodeHexString(BigEndianBigInteger.toByteArray(n));
//        System.out.println(myHexing);

        String exampleNinHex = "a1f8160ae2e3c9b465ce8d2d656263362b927dbe29e1f02477fc1625cc90a136e38bd93497c5b6ea63dd7711e67c7429f956b0fb8a8f089adc4b69893cc1333f53edd019b87784252fec914fe4857769594bea4280d32c0f55bf62944f130396bc6e9bdf6ebdd2bda3678eeca0c668f701b38dbffb38c8342ce2fe6d27fade4a5a4874979dd4b9cf9adec4c75b05852c2c0f5ef8a5c1750392f944e8ed64c110c6b647609aa4783aeb9c6c9ad755313050638b83665c6f6f7a82a396702a1f641b82d3ebf2392219491fb686872c5716f50af8358d9a8b9d17c340728f7f87d89a18d8fcab67ad84590c2ecf759339363c07034d6f606f9e21e05456cae5e9a1";

//               System.out.println(exampleNinHex);
//
//        System.out.println(exampleNinHex.equals(myHexing));


        BigInteger publicExponent = ExampleRsaKeyFromJws.PUBLIC_KEY.getPublicExponent();
        myHexing = Hex.encodeHexString(BigEndianBigInteger.toByteArray(publicExponent));

//        System.out.println(myHexing);
        String pubExEx = "010001";
//        System.out.println(pubExEx);
//        System.out.println(pubExEx.equals(myHexing));
//        testJwsRsaExample();
//
//        System.out.println("+++++++++++++++++++++");
//
//        testJwsHmacExample();

        String jwks = "{\"keys\":[{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"5\",\"mod\":\"jEEnYC3tBKkYVRY7DAzWxIjxjptoKlm_GfIO2WbRIudVdS-vfr9HMEO2q3-XO10a8MQCFHQOyOdQdhtGsMyWrXbdfV6ivfPM7_2MO1UuYgV2tDhLzjjShzeMkomrsB_nAWtX8Qun1XsRBu_GIdJbd4WMoTbNVaaAf1-U8ieHDNE\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"4\",\"mod\":\"6cKl2TEtFUfBs4zZCatIov1F7SDu_0azkbKzG-0HhiFyHsGZeP4EtHH9tXEJcKNLxZXeFCO9yK_n6LS4KiH87fRYAs6aHiNHdaPWo5D4kdiYG-HNAEMqJzWR9eykUomuUZRe6fiKLOBcgdWjstB7I5PAqFy75RXDLqFuRPDWub8\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"3\",\"mod\":\"h7Jep0xSV6s-fZoHzQuZGT5g_I6q4chSrO0-yxYMehbmds9JFoJxQ2lcBnhkl8C4QudNk93Nyp_VGV33sytW7-22JpN2GFrxI80xzbZlZ7B1pxAZdP74C27YFJEBnwineiLowlHjc0OFQ-gwso6MYzwxV8NttwIDq4tBqbs1pxE\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"2\",\"mod\":\"ktR38dP3vITaViAE_Wg4YX0CApH40QvtXKea-1GSsW8Yl1VxIq_dOcZPKgLLWm9is5g9WZuCYj3sRVfrRmKXoN0qjUX-ZC-L4oxMJzNMGIZ93XiiKC1bdMnHXhdkRhZB5M_-qlx5Cmw69qeQ_wuHJwV4hDjbQeUcfoZySCppfNM\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"1\",\"mod\":\"y2ZGB-Ol6kmpFqWxc02xrjocp9VS9JsstaZl6Gy9hDmKXkkuKnap4hcWcHfF2PK0uLMJYUE_3se1dNBhR3M2ByOajHiSBGj_y_FYiTdjHb2bpkAJQ7wVT9ncT_Fx7V_kYvIevy1NBCr47bwqz4WJcUyZbHXFFoaOYnWHBVyjUl0\",\"exp\":\"AQAB\"},{\"alg\":\"RSA\",\"use\":\"sig\",\"kid\":\"0\",\"mod\":\"sjMKXtiyCUz6kAT9H9Ve0cHnWxJFN9d_eHNtk318QsJqt86BfhTlpdY7DbE7M0MVyVXIMTjXUDHnvZ4tCDXB3Q\",\"exp\":\"AQAB\"}]}";
        JsonWebKeySet jwkset = new JsonWebKeySet(jwks);
        JsonWebKey webKey = jwkset.getKey("4");
        RsaJsonWebKey rsaWebKey = (RsaJsonWebKey) webKey;

        myHexing = Hex.encodeHexString(BigEndianBigInteger.toByteArray(rsaWebKey.getRSAPublicKey().getModulus()));
        System.out.println(myHexing);

        myHexing = Hex.encodeHexString(BigEndianBigInteger.toByteArray(rsaWebKey.getRSAPublicKey().getPublicExponent()));
        System.out.println(myHexing);




    }

    


    public static void testJwsRsaExample() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException
    {
        String header = "{\"alg\":\"RS256\"}";
        Base64 base64url = getBase64url();
        String encodedHeader = base64url.encodeToString(StringUtils.getBytesUtf8(header));
        System.out.println(encodedHeader);
        System.out.println("eyJhbGciOiJSUzI1NiJ9");

        String payload = getPayload();
        String encodedPayload = base64url.encodeToString(StringUtils.getBytesUtf8(payload));

        String securedInput = encodedHeader + DOT + encodedPayload;

        System.out.println(securedInput);
        String exampleSecInput = "eyJhbGciOiJSUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        System.out.println(exampleSecInput);


        int[] examplePrivateKxpo = {18, 174, 113, 164, 105, 205, 10, 43, 195, 126, 82,
           108, 69, 0, 87, 31, 29, 97, 117, 29, 100, 233, 73,
           112, 123, 98, 89, 15, 157, 11, 165, 124, 150, 60, 64,
           30, 63, 207, 47, 44, 211, 189, 236, 136, 229, 3, 191,
           198, 67, 155, 11, 40, 200, 47, 125, 55, 151, 103, 31,
           82, 19, 238, 216, 193, 90, 37, 216, 213, 206, 160, 2,
           94, 227, 171, 46, 139, 127, 121, 33, 111, 198, 59,
           234, 86, 39, 83, 180, 6, 68, 198, 161, 81, 39, 217,
           178, 149, 69, 64, 160, 187, 225, 163, 5, 86, 152, 45,
           78, 159, 222, 95, 100, 37, 241, 77, 75, 113, 52, 65,
           181, 93, 199, 59, 155, 74, 237, 204, 146, 172, 227,
           146, 126, 55, 245, 125, 12, 253, 94, 117, 129, 250,
           81, 44, 143, 73, 97, 169, 235, 11, 128, 248, 168, 7,
           70, 114, 138, 85, 255, 70, 71, 31, 52, 37, 6, 59,
           157, 83, 100, 47, 94, 222, 30, 132, 214, 19, 8, 26,
           250, 92, 34, 208, 81, 40, 91, 214, 59, 148, 59, 86,
           93, 137, 138, 5, 104, 84, 19, 229, 60, 60, 108, 101,
           37, 255, 31, 227, 78, 61, 220, 112, 240, 213, 100,
           80, 253, 164, 139, 161, 46, 16, 78, 157, 235, 159,
           184, 24, 129, 225, 196, 189, 242, 93, 146, 71, 244,
           80, 200, 101, 146, 121, 104, 231, 115, 52, 244, 65,
           79, 117, 167, 80, 225, 57, 84, 110, 58, 138, 115,
           157};

        int [] exampleModulus = {161, 248, 22, 10, 226, 227, 201, 180, 101, 206, 141,
            45, 101, 98, 99, 54, 43, 146, 125, 190, 41, 225, 240,            
            36, 119, 252, 22, 37, 204, 144, 161, 54, 227, 139,               
            217, 52, 151, 197, 182, 234, 99, 221, 119, 17, 230,              
            124, 116, 41, 249, 86, 176, 251, 138, 143, 8, 154,               
            220, 75, 105, 137, 60, 193, 51, 63, 83, 237, 208, 25,            
            184, 119, 132, 37, 47, 236, 145, 79, 228, 133, 119,              
            105, 89, 75, 234, 66, 128, 211, 44, 15, 85, 191, 98,             
            148, 79, 19, 3, 150, 188, 110, 155, 223, 110, 189,               
            210, 189, 163, 103, 142, 236, 160, 198, 104, 247, 1,             
            179, 141, 191, 251, 56, 200, 52, 44, 226, 254, 109,              
            39, 250, 222, 74, 90, 72, 116, 151, 157, 212, 185,               
            207, 154, 222, 196, 199, 91, 5, 133, 44, 44, 15, 94,             
            248, 165, 193, 117, 3, 146, 249, 68, 232, 237, 100,              
            193, 16, 198, 182, 71, 96, 154, 164, 120, 58, 235,               
            156, 108, 154, 215, 85, 49, 48, 80, 99, 139, 131,                
            102, 92, 111, 111, 122, 130, 163, 150, 112, 42, 31,              
            100, 27, 130, 211, 235, 242, 57, 34, 25, 73, 31, 182,            
            134, 135, 44, 87, 22, 245, 10, 248, 53, 141, 154,                
            139, 157, 23, 195, 64, 114, 143, 127, 135, 216, 154,             
            24, 216, 252, 171, 103, 173, 132, 89, 12, 46, 207,               
            117, 147, 57, 54, 60, 7, 3, 77, 111, 96, 111, 158,               
            33, 224, 84, 86, 202, 229, 233, 161};

        BigInteger modulus = new BigInteger(1, getKey(exampleModulus));
        System.out.println(modulus);
        BigInteger privateExponent = new BigInteger(1, getKey(examplePrivateKxpo));
        System.out.println(privateExponent);


        KeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(StringUtils.getBytesUtf8(securedInput));
        byte[] signatureBytes = signer.sign();

        String b64sig = base64url.encodeToString(signatureBytes);
        System.out.println(b64sig);

        String exampleSig = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" +
                "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" +
                "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" +
                "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" +
                "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" +
                "p0igcN_IoypGlUPQGe77Rw";
        System.out.println(exampleSig);
        System.out.println(exampleSig.equals(b64sig));
    }


    public static void testJwsHmacExample() throws NoSuchAlgorithmException, InvalidKeyException
    {
        Base64 b64url = getBase64url();

        String header = "{\"typ\":\"JWT\"," + newline +
                " \"alg\":\"HS256\"}";
        System.out.println(header);


        byte[] headerBytes = StringUtils.getBytesUtf8(header);
        System.out.println(Arrays.toString(headerBytes));
        String encodedHeader = b64url.encodeToString(headerBytes);

        System.out.println(encodedHeader);
        String exmpleEncodedHeader = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";
        System.out.println(exmpleEncodedHeader);
        System.out.println(encodedHeader.equals(exmpleEncodedHeader));


        byte[] bytes1 = b64url.decode(exmpleEncodedHeader);
        String s1 = StringUtils.newStringUtf8(bytes1);
        System.out.println(s1);

        String payload = getPayload();


        byte[] payloadBytes = StringUtils.getBytesUtf8(payload);
        String encodedPayload = b64url.encodeToString(payloadBytes);

        System.out.println(encodedPayload);
        String exampleEncodedPayload = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        System.out.println(exampleEncodedPayload);
        System.out.println(exampleEncodedPayload.equals(exampleEncodedPayload));

        String securedInput = exmpleEncodedHeader + DOT + exampleEncodedPayload;
        StringUtils.getBytesUtf8(securedInput);

        int[] keyFromExample = {3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
                       143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
                       46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
                       98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
                       208, 128, 163};

        byte[] keyBytes = getKey(keyFromExample);

        System.out.println(Arrays.toString(keyBytes));

        String jceAlgo = "HMACSHA256";
        Mac mac = Mac.getInstance(jceAlgo);
        Key key = new SecretKeySpec(keyBytes, jceAlgo);
        mac.init(key);

        byte[] macBytes = mac.doFinal(StringUtils.getBytesUtf8(securedInput));
        String sigValue = b64url.encodeToString(macBytes);
        System.out.println(sigValue);
        String exmpaleSigValue = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        System.out.println(exmpaleSigValue);
        System.out.println(exmpaleSigValue.equals(sigValue));

        String jws = encodedHeader + DOT + encodedPayload + DOT + sigValue;

        String exampleJWS = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
                "." +
                "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
                "." +
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        System.out.println(jws);
        System.out.println(exampleJWS);
        System.out.println(exampleJWS.equals(jws));
    }

    private static String getPayload()
    {
        return "{\"iss\":\"joe\"," + newline + " \"exp\":1300819380," + newline +" \"http://example.com/is_root\":true}";
    }

    private static Base64 getBase64url()
    {
        return new Base64(-1, null, true);
    }

    private static byte[] getKey(int[] keyFromExample)
    {
        return ByteUtil.convertUnsignedToSignedTwosComp(keyFromExample);
    }
}
