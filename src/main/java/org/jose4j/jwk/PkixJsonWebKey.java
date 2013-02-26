package org.jose4j.jwk;

import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;

import java.security.cert.*;
import java.util.*;

/**
 */
public class PkixJsonWebKey extends JsonWebKey
{
    public static final String X509_CERTIFICATE_CHAIN = "x5c";

    public static final String KEY_TYPE = "PKIX";

    private X509Util x509Util = new X509Util();

    private List<X509Certificate> certificateChain;
    private List<String> x5cStrings;

    public PkixJsonWebKey(List<X509Certificate> certificates)
    {
        this(certificates.toArray(new X509Certificate[certificates.size()]));
    }

    public PkixJsonWebKey(X509Certificate... certificates)
    {
        super(certificates[0].getPublicKey());
        certificateChain = Arrays.asList(certificates);

        x5cStrings = new ArrayList<String>(certificateChain.size());

       for (X509Certificate cert : certificateChain)
       {
           String b64EncodedDer = x509Util.toBase64Der(cert);
           x5cStrings.add(b64EncodedDer);
       }
    }

    public PkixJsonWebKey(Map<String, Object> params) throws JoseException
    {
        super(params);
        x5cStrings = JsonHelp.getStringArray(params, X509_CERTIFICATE_CHAIN);
        certificateChain = new ArrayList<X509Certificate>(x5cStrings.size());

        for (String b64EncodedDer : x5cStrings)
        {
            X509Certificate x509Certificate = x509Util.fromBase64Der(b64EncodedDer);
            certificateChain.add(x509Certificate);
        }

        publicKey = getX509Certificate().getPublicKey();
    }

    @Override
    public String getKeyType()
    {
        return KEY_TYPE;
    }

    @Override
    protected void fillTypeSpecificParams(Map<String, Object> params)
    {
        params.put(X509_CERTIFICATE_CHAIN, x5cStrings);
    }

    public List<X509Certificate> getX509CertificateChain()
    {
        return certificateChain;
    }

    public X509Certificate getX509Certificate()
    {
        return certificateChain.isEmpty() ? null : certificateChain.get(0);
    }
}
