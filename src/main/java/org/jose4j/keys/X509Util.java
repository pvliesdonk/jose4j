package org.jose4j.keys;

import org.apache.commons.codec.binary.Base64;
import org.jose4j.lang.JoseException;

import java.io.ByteArrayInputStream;
import java.security.cert.*;

/**
 */
public class X509Util
{
    private static final String FACTORY_TYPE = "X.509";

    private CertificateFactory certFactory;

    private Base64 base64 = new Base64();

    public X509Util()
    {
        try
        {
            certFactory = CertificateFactory.getInstance(FACTORY_TYPE);
        }
        catch (CertificateException e)
        {
            throw new IllegalStateException("Couldn't find "+ FACTORY_TYPE + " CertificateFactory!?!", e);
        }
    }

    public String toBase64Der(X509Certificate x509Certificate)
    {
        try
        {
            byte[] der = x509Certificate.getEncoded();
            return base64.encodeToString(der);
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalStateException("Unexpected problem getting encoded certificate.", e);
        }
    }

    public X509Certificate fromBase64Der(String b64EncodedDer) throws JoseException
    {
        byte[] der = base64.decode(b64EncodedDer);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(der);
        try
        {
            Certificate certificate = certFactory.generateCertificate(byteArrayInputStream);
            return (X509Certificate) certificate;
        }
        catch (CertificateException e)
        {
            throw new JoseException("Unable to convert " + b64EncodedDer + " value to X509Certificate: " + e, e);
        }
    }


}
