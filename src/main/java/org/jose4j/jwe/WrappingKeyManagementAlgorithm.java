package org.jose4j.jwe;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwa.AlgorithmInfo;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 */
public class WrappingKeyManagementAlgorithm extends AlgorithmInfo implements KeyManagementAlgorithm
{
    private final Log log = LogFactory.getLog(this.getClass());

    public WrappingKeyManagementAlgorithm(String javaAlg, String alg)
    {
        setJavaAlgorithm(javaAlg);
        setAlgorithmIdentifier(alg);
    }

    public ContentEncryptionKeys manageForEncrypt(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers) throws JoseException
    {
        byte[] contentEncryptionKey = ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength());
        return manageForEnc(managementKey, cekDesc, contentEncryptionKey);
    }

    protected ContentEncryptionKeys manageForEnc(Key managementKey, ContentEncryptionKeyDescriptor cekDesc, byte[] contentEncryptionKey) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());

        try
        {
            cipher.init(Cipher.WRAP_MODE, managementKey);
            String contentEncryptionKeyAlgorithm = cekDesc.getContentEncryptionKeyAlgorithm();
            byte[] encryptedKey = cipher.wrap(new SecretKeySpec(contentEncryptionKey, contentEncryptionKeyAlgorithm));
            return new ContentEncryptionKeys(contentEncryptionKey, encryptedKey);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new JoseException("Unable to encrypt the Content Encryption Key", e);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Unable to encrypt the Content Encryption Key", e);
        }
    }

    public Key manageForDecrypt(Key managementKey, byte[] encryptedKey, ContentEncryptionKeyDescriptor cekDesc, Headers headers) throws JoseException
    {
        Cipher cipher = CipherUtil.getCipher(getJavaAlgorithm());

        try
        {
            cipher.init(Cipher.UNWRAP_MODE, managementKey);
        }
        catch (InvalidKeyException e)
        {
            throw new JoseException("Unable to initialize cipher for key decryption", e);
        }

        String cekAlg = cekDesc.getContentEncryptionKeyAlgorithm();

        try
        {
            return cipher.unwrap(encryptedKey, cekAlg, Cipher.SECRET_KEY);
        }
        catch (Exception e)
        {
            if (log.isDebugEnabled())
            {
                log.debug("Key unwrap failed. Substituting a randomly generated CEK and proceeding.", e);
            }

            /*
                TODO - is this good enough for step 10 from
                http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-14#section-5.2
                ?  And should it be doing this for the other key wrapping/encrypting algs? OAEP and AES Key wrap?
                    To mitigate the attacks described in RFC 3218 [RFC3218], the
                    recipient MUST NOT distinguish between format, padding, and
                    length errors of encrypted keys.  It is strongly recommended, in
                    the event of receiving an improperly formatted key, that the
                    receiver substitute a randomly generated CEK and proceed to the
                    next step, to mitigate timing attacks.
             */
            byte[] bytes = ByteUtil.randomBytes(cekDesc.getContentEncryptionKeyByteLength());
            return new SecretKeySpec(bytes, cekAlg);
        }
    }
}
