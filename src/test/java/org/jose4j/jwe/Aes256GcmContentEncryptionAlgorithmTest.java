package org.jose4j.jwe;

import org.hamcrest.CoreMatchers;
import org.jose4j.base64url.Base64Url;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.junit.Assert;
import org.junit.Test;

import java.security.Security;

/**
 */
public class Aes256GcmContentEncryptionAlgorithmTest
{
    @Test
    public void testExampleEncryptFromJweAppendix1() throws JoseException
    {
        // seems that maybe "AES/GCM/NoPadding" isn't supported with the standard JCE with the Java 7
        // so skipping this test for now...
        if (true) return;

        // and BC supports GCM but maybe not via the standard JCE interfaces (until BC v 1.50)
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#appendix-A.1
        String plaintextText = "The true sign of intelligence is not knowledge but imagination.";
        byte[] plainText = StringUtil.getBytesUtf8(plaintextText);

        String encodedHeader = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ";
        byte[] aad = StringUtil.getBytesAscii(encodedHeader);

        byte[] cek = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
                212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
                234, 64, 252});

        byte[] iv = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219});

        Aes256GcmContentEncryptionAlgorithm aesGcmContentEncryptionAlg = new Aes256GcmContentEncryptionAlgorithm();

        ContentEncryptionParts encryptionParts = aesGcmContentEncryptionAlg.encrypt(plainText, aad, cek, iv);

        Base64Url base64Url = new Base64Url();

        byte[] ciphertext = encryptionParts.getCiphertext();
        String encodedJweCiphertext = "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A";
        Assert.assertThat(encodedJweCiphertext, CoreMatchers.equalTo(base64Url.base64UrlEncode(ciphertext)));

        byte[] authenticationTag = encryptionParts.getAuthenticationTag();
        String encodedAuthenticationTag = "XFBoMYUZodetZdvTiFvSkQ";
        Assert.assertThat(encodedAuthenticationTag, CoreMatchers.equalTo(base64Url.base64UrlEncode(authenticationTag)));

        ContentEncryptionParts parts = new ContentEncryptionParts(iv, ciphertext, authenticationTag);
        byte[] decrypted = aesGcmContentEncryptionAlg.decrypt(parts, aad, cek, null);
        Assert.assertArrayEquals(plainText, decrypted);
    }
}
