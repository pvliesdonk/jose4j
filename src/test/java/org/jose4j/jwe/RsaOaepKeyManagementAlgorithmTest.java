package org.jose4j.jwe;

import junit.framework.TestCase;
import org.jose4j.base64url.Base64Url;
import org.jose4j.keys.AesKey;
import org.jose4j.keys.ExampleRsaJwksFromJwe;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 */
public class RsaOaepKeyManagementAlgorithmTest extends TestCase
{
    public void testJweExampleA1() throws JoseException
    {
        String encodedEncryptedKey =
                "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe" +
                "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb" +
                "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV" +
                "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8" +
                "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi" +
                "6UklfCpIMfIjf7iGdXKHzg";
        Base64Url base64Url = new Base64Url();
        byte[] encryptedKey = base64Url.base64UrlDecode(encodedEncryptedKey);

        RsaOaepKeyManagementAlgorithm keyManagementAlgorithm = new RsaOaepKeyManagementAlgorithm();
        PrivateKey privateKey = ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey();
        ContentEncryptionKeyDescriptor cekDesc = new ContentEncryptionKeyDescriptor(256, AesKey.ALGORITHM);
        Key key = keyManagementAlgorithm.manageForDecrypt(privateKey, encryptedKey, cekDesc, null);

        byte[] cekBytes = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{177, 161, 244, 128, 84, 143, 225,
                115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46,
                122, 234, 64, 252});

        byte[] encoded = key.getEncoded();
        assertTrue(Arrays.toString(encoded), Arrays.equals(cekBytes, encoded));
    }

    public void testRoundTrip() throws JoseException
    {
        RsaOaepKeyManagementAlgorithm oaep = new RsaOaepKeyManagementAlgorithm();
        ContentEncryptionKeyDescriptor cekDesc = new ContentEncryptionKeyDescriptor(128, AesKey.ALGORITHM);
        PublicKey publicKey = ExampleRsaJwksFromJwe.APPENDIX_A_1.getPublicKey();
        ContentEncryptionKeys contentEncryptionKeys = oaep.manageForEncrypt(publicKey, cekDesc, null);

        byte[] encryptedKey = contentEncryptionKeys.getEncryptedKey();

        PrivateKey privateKey = ExampleRsaJwksFromJwe.APPENDIX_A_1.getPrivateKey();
        Key key = oaep.manageForDecrypt(privateKey, encryptedKey, cekDesc, null);

        byte[] cek = contentEncryptionKeys.getContentEncryptionKey();
        assertTrue(Arrays.equals(cek, key.getEncoded()));
    }
}
