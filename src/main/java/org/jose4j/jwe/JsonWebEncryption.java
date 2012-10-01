package org.jose4j.jwe;

import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.ByteGenerator;
import org.jose4j.lang.DefaultByteGenerator;
import org.jose4j.lang.StringUtil;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.base64url.Base64Url;

import javax.crypto.SecretKey;

/**
 */
public class JsonWebEncryption extends JsonWebStructure
{
    private Base64Url base64url = new Base64Url();
    
    private String plaintextCharEncoding = StringUtil.UTF_8;
    private byte[] plaintext;

    private SecretKey contentMasterKey;
    private SecretKey contentEncryptionKey;
    private SecretKey contentIntegrityKey; 

    private ByteGenerator byteGenerator = new DefaultByteGenerator();

    public void setByteGenerator(ByteGenerator byteGenerator)
    {
        this.byteGenerator = byteGenerator;
    }

    public void setPlainTextCharEncoding(String plaintextCharEncoding)
    {
        this.plaintextCharEncoding = plaintextCharEncoding;
    }

    public void setPlaintext(byte[] plaintext)
    {
        this.plaintext = plaintext;
    }

    public void setPlaintext(String plaintext)
    {
        this.plaintext = StringUtil.getBytesUnchecked(plaintext, plaintextCharEncoding);
    }

    public String getPlaintextString()
    {
        return StringUtil.newString(plaintext, plaintextCharEncoding);
    }

    public byte[] getPlaintextBytes()
    {
        return plaintext;
    }


    private SymmetricEncryptionAlgorithm getSymmetricEncryptionAlgorithm()
    {
        String algo = getHeader(HeaderParameterNames.ENCRYPTION_METHOD);
        if (algo == null)
        {
            throw new IllegalStateException(HeaderParameterNames.ENCRYPTION_METHOD + " header not set.");
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        return factoryFactory.getSymmetricEncryptionAlgorithm(algo);
    }

    private KeyEncryptionAlgorithm getKeyEncryptionAlgorithm()
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new IllegalStateException(HeaderParameterNames.ALGORITHM + " header not set.");
        }
        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        return factoryFactory.getKeyEncryptionAlgorithm(algo);
    }


    public String getCompactSerialization()
    {
        SymmetricEncryptionAlgorithm symmetricEncryptionAlgorithm = getSymmetricEncryptionAlgorithm();
        byte[] contentMasterKeyBytes = byteGenerator.randomBytes(symmetricEncryptionAlgorithm.getKeySize() / 8);
//        contentMasterKey = new SecretKeySpec(keyBytes, symmetricEncryptionAlgorithm.getKeyAlgo());
        KeyEncryptionAlgorithm keyEncryptionAlgorithm = getKeyEncryptionAlgorithm();
        byte[] jweEncryptedKey = keyEncryptionAlgorithm.encrypt(getKey(), contentMasterKeyBytes);
        String encodedJweEncryptedKey = base64url.base64UrlEncode(jweEncryptedKey);

        return "todo.getthis.working.ok";
    }
    /*

   1.   Generate a random Content Master Key (CMK).  The CMK MUST have a
        length at least equal to that of the larger of the required
        encryption or integrity keys and MUST be generated randomly.

        See RFC 4086 [RFC4086] for considerations on generating random
        values.

   2.   Encrypt the CMK for the recipient (see Section 8) and let the
        result be the JWE Encrypted Key.

   3.   Base64url encode the JWE Encrypted Key to create the Encoded JWE
        Encrypted Key.

   4.   Generate a random Initialization Vector (IV) (if required for
        the algorithm).

   5.   If not using an AEAD algorithm, run the key derivation algorithm
        (see Section 7) to generate the Content Encryption Key (CEK) and
        the Content Integrity Key (CIK); otherwise (when using an AEAD
        algorithm), set the CEK to be the CMK.

   6.   Compress the Plaintext if a "zip" parameter was included.

   7.   Serialize the (compressed) Plaintext into a bitstring M.

   8.   Encrypt M using the CEK and IV to form the bitstring C.

   9.   Base64url encode C to create the Encoded JWE Ciphertext.

   10.  Create a JWE Header containing the encryption parameters used.
        Note that white space is explicitly allowed in the
        representation and no canonicalization need be performed before
        encoding.

   11.  Base64url encode the bytes of the UTF-8 representation of the
        JWE Header to create the Encoded JWE Header.

   12.  If not using an AEAD algorithm, run the integrity algorithm (see
        Section 9) using the CIK to compute the JWE Integrity Value;
        otherwise (when using an AEAD algorithm), set the JWE Integrity
        Value to be the empty byte string.

   13.  Base64url encode the JWE Integrity Value to create the Encoded
        JWE Integrity Value.

   14.  The four encoded parts, taken together, are the result.  The
        Compact Serialization of this result is the concatenation of the
        Encoded JWE Header, the Encoded JWE Encrypted Key, the Encoded
        JWE Ciphertext, and the Encoded JWE Integrity Value in that
        order, with the four strings being separated by period ('.')
        characters.
     */
}
