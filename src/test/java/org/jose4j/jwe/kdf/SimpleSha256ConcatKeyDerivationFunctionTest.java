package org.jose4j.jwe.kdf;

import junit.framework.TestCase;

import java.util.Arrays;

import org.jose4j.lang.ByteUtil;
import static org.jose4j.jwe.kdf.ShaConcatKeyDerivationFunction.*;
import org.jose4j.jwe.kdf.ShaConcatKeyDerivationFunction;

/**
 */
public class SimpleSha256ConcatKeyDerivationFunctionTest extends TestCase
{
    public void testGetReps()
    {
        ShaConcatKeyDerivationFunction kdf = new Sha256ConcatKeyDerivationFunction();
        assertEquals(1, kdf.getReps(256));
        assertEquals(2, kdf.getReps(384));
        assertEquals(2, kdf.getReps(512));
        assertEquals(4, kdf.getReps(1024));
        assertEquals(5, kdf.getReps(1025));
    }

    public void testSizeEtc256()
    {
        testKdfSizeAndOtherStuff(256);
    }

    public void testSizeEtc384()
    {
        testKdfSizeAndOtherStuff(384);
    }

    public void testSizeEtc512()
    {
        testKdfSizeAndOtherStuff(512);
    }

    public void testKdfSizeAndOtherStuff(int keydatalen)
    {
        ShaConcatKeyDerivationFunction kdf1 = new Sha256ConcatKeyDerivationFunction();
        byte[] secret = {1, 62, 3, 4, 9, 83, 123, 12, 111, 1, 1, 0, -1, 8, 7 , 12, 45, 118, 99, 9};
        byte[] keyBytes1 = kdf1.kdf(secret, keydatalen, INTEGRITY_LABEL);
        assertEquals(keydatalen, keyBytes1.length * 8);

        ShaConcatKeyDerivationFunction kdf2 = new Sha256ConcatKeyDerivationFunction();
        byte[] keyBytes2 = kdf2.kdf(secret, keydatalen, INTEGRITY_LABEL);

        assertTrue(Arrays.equals(keyBytes1, keyBytes2));

        byte[] keyBytes3 = kdf2.kdf(secret, keydatalen, ENCRYPTION_LABEL);

        assertFalse(Arrays.equals(keyBytes1, keyBytes3));
    }

    public void testWTKDF()
    {
        byte[] integrityBytes = INTEGRITY_LABEL;
        System.out.println(Arrays.toString(integrityBytes));

        byte[] lengthBytes = ByteUtil.getBytes(integrityBytes.length);

        byte[] bytes = ByteUtil.concat(lengthBytes, integrityBytes);
        System.out.println(Arrays.toString(bytes));
    }

    public void testJune20EmailExample1()
    {
        /*
            EXAMPLE 1:

                256-bit Content Master Key (CMK)
                256-bit derived Content Encryption Key (CEK)
                256-bit derived Content Integrity Key (CIK)


            CMK1 value:  [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206,
            107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207]

            Deriving CEK1...

            Round 1 hash_input: [0, 0, 0, 1, 4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250,
            63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240,
            143, 156, 44, 207, 69, 110, 99, 114, 121, 112, 116, 105, 111, 110]
            Round 1 hash_output: [249, 255, 87, 218, 224, 223, 221, 53, 204, 121, 166, 130, 195, 184, 50, 69,
            11, 237, 202, 71, 10, 96, 59, 199, 140, 88, 126, 147, 146, 113, 222, 41]

            CEK1 value: [249, 255, 87, 218, 224, 223, 221, 53, 204, 121, 166, 130, 195, 184, 50, 69,
            11, 237, 202, 71, 10, 96, 59, 199, 140, 88, 126, 147, 146, 113, 222, 41]

            Deriving CIK1...

            Round 1 hash_input: [0, 0, 0, 1, 4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250,
            63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240,
            143, 156, 44, 207, 73, 110, 116, 101, 103, 114, 105, 116, 121]
            Round 1 hash_output: [218, 209, 130, 50, 169, 45, 70, 214, 29, 187, 123, 20, 3, 158, 111, 122,
            182, 94, 57, 133, 245, 76, 97, 44, 193, 80, 81, 246, 115, 177, 225, 159]

            CIK1 value: [218, 209, 130, 50, 169, 45, 70, 214, 29, 187, 123, 20, 3, 158, 111, 122,
            182, 94, 57, 133, 245, 76, 97, 44, 193, 80, 81, 246, 115, 177, 225, 159]
         */

        byte[] cmk = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{
                4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107,
                124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207});


        ShaConcatKeyDerivationFunction kdf = new Sha256ConcatKeyDerivationFunction();
        byte[] cek = kdf.kdf(cmk, 256, ShaConcatKeyDerivationFunction.ENCRYPTION_LABEL);

        int[] cekInts ={249, 255, 87, 218, 224, 223, 221, 53, 204, 121, 166, 130, 195, 184, 50,
                69, 11, 237, 202, 71, 10, 96, 59, 199, 140, 88, 126, 147, 146, 113, 222, 41};
        assertTrue(Arrays.equals(cekInts, ByteUtil.convertSignedTwosCompToUnsigned(cek)));

        byte[] cik = kdf.kdf(cmk, 256, ShaConcatKeyDerivationFunction.INTEGRITY_LABEL);
        int[] cikInts = {218, 209, 130, 50, 169, 45, 70, 214, 29, 187, 123, 20, 3, 158, 111, 122,
                182, 94, 57, 133, 245, 76, 97, 44, 193, 80, 81, 246, 115, 177, 225, 159};

        assertTrue(Arrays.equals(cikInts, ByteUtil.convertSignedTwosCompToUnsigned(cik)));
    }

    public void testJune20EmailExample2()
    {
        /*
            EXAMPLE 2:

                512-bit Content Master Key (CMK)
                128-bit derived Content Encryption Key (CEK)
                512-bit derived Content Integrity Key (CIK)


            CMK2 value: [148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193, 61, 34, 239, 226,
            109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176, 68, 119, 13, 34,
            49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138, 67, 23, 153, 83,
            81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156, 249, 7, 225, 168]


            Deriving CEK2...

            Round 1 hash_input: [0, 0, 0, 1, 148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193,
            61, 34, 239, 226, 109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176,
            68, 119, 13, 34, 49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138,
            67, 23, 153, 83, 81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156,
            249, 7, 225, 168, 69, 110, 99, 114, 121, 112, 116, 105, 111, 110]

            Round 1 hash_output: [137, 5, 92, 9, 17, 47, 17, 86, 253, 235, 34, 247, 121, 78, 11, 144,
            10, 172, 38, 247, 108, 243, 201, 237, 95, 80, 49, 150, 116, 240, 159, 64]


            CEK2 value: [137, 5, 92, 9, 17, 47, 17, 86, 253, 235, 34, 247, 121, 78, 11, 144]


            Deriving CIK2...

            Round 1 hash_input: [0, 0, 0, 1, 148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193,
            61, 34, 239, 226, 109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176,
            68, 119, 13, 34, 49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138,
            67, 23, 153, 83, 81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156,
            249, 7, 225, 168, 73, 110, 116, 101, 103, 114, 105, 116, 121]
            Round 1 hash_output: [11, 179, 132, 177, 171, 24, 126, 19, 113, 1, 200, 102, 100, 74, 88, 149,
            31, 41, 71, 57, 51, 179, 106, 242, 113, 211, 56, 56, 37, 198, 57, 17]

            Round 2 hash_input: [0, 0, 0, 2, 148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193,
            61, 34, 239, 226, 109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176,
            68, 119, 13, 34, 49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138,
            67, 23, 153, 83, 81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156,
            249, 7, 225, 168, 73, 110, 116, 101, 103, 114, 105, 116, 121]
            Round 2 hash_output: [149, 209, 221, 113, 40, 191, 95, 252, 142, 254, 141, 230, 39, 113, 139, 84,
            44, 156, 247, 47, 223, 101, 229, 180, 82, 231, 38, 96, 170, 119, 236, 81]

            CIK2 value: [11, 179, 132, 177, 171, 24, 126, 19, 113, 1, 200, 102, 100, 74, 88, 149,
            31, 41, 71, 57, 51, 179, 106, 242, 113, 211, 56, 56, 37, 198, 57, 17,
            149, 209, 221, 113, 40, 191, 95, 252, 142, 254, 141, 230, 39, 113, 139, 84,
            44, 156, 247, 47, 223, 101, 229, 180, 82, 231, 38, 96, 170, 119, 236, 81]
         */

        byte[] cmk = ByteUtil.convertUnsignedToSignedTwosComp(new int[]{
                148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193, 61, 34, 239, 226,
            109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176, 68, 119, 13, 34,
            49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138, 67, 23, 153, 83,
            81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156, 249, 7, 225, 168});


        ShaConcatKeyDerivationFunction kdf = new Sha256ConcatKeyDerivationFunction();
        byte[] cek = kdf.kdf(cmk, 128, ShaConcatKeyDerivationFunction.ENCRYPTION_LABEL);

        int[] cekInts ={137, 5, 92, 9, 17, 47, 17, 86, 253, 235, 34, 247, 121, 78, 11, 144};
        assertTrue(Arrays.equals(cekInts, ByteUtil.convertSignedTwosCompToUnsigned(cek)));

        byte[] cik = kdf.kdf(cmk, 512, ShaConcatKeyDerivationFunction.INTEGRITY_LABEL);
        int[] cikInts = {11, 179, 132, 177, 171, 24, 126, 19, 113, 1, 200, 102, 100, 74, 88, 149,
            31, 41, 71, 57, 51, 179, 106, 242, 113, 211, 56, 56, 37, 198, 57, 17,
            149, 209, 221, 113, 40, 191, 95, 252, 142, 254, 141, 230, 39, 113, 139, 84,
            44, 156, 247, 47, 223, 101, 229, 180, 82, 231, 38, 96, 170, 119, 236, 81};

        assertTrue(Arrays.equals(cikInts, ByteUtil.convertSignedTwosCompToUnsigned(cik)));
    }



}
