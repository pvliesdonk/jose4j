package org.jose4j.jwk;

import org.jose4j.json.JsonUtil;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.JsonHelp;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 */
public abstract class PublicJsonWebKey extends JsonWebKey
{
    // todo x5c etc, fun
    public static final String X509_CERTIFICATE_CHAIN_PARAMETER = "x5c";
    public static final String X509_THUMBPRINT_PARAMETER = "x5t";
    public static final String X509_URL_PARAMETER = "x5u";

    protected boolean writeOutPrivateKeyToJson;
    protected PrivateKey privateKey;

    private List<X509Certificate> certificateChain;

    protected PublicJsonWebKey(PublicKey publicKey)
    {
        super(publicKey);
    }

    protected PublicJsonWebKey(Map<String, Object> params) throws JoseException
    {
        super(params);

        if (params.containsKey(X509_CERTIFICATE_CHAIN_PARAMETER))
        {
            List<String> x5cStrings = JsonHelp.getStringArray(params, X509_CERTIFICATE_CHAIN_PARAMETER);
            certificateChain = new ArrayList<X509Certificate>(x5cStrings.size());

            X509Util x509Util = new X509Util();

            for (String b64EncodedDer : x5cStrings)
            {
                X509Certificate x509Certificate = x509Util.fromBase64Der(b64EncodedDer);
                certificateChain.add(x509Certificate);
            }
        }
    }

    protected abstract void fillPublicTypeSpecificParams(Map<String,Object> params);
    protected abstract void fillPrivateTypeSpecificParams(Map<String,Object> params);

    protected void fillTypeSpecificParams(Map<String,Object> params)
    {
        fillPublicTypeSpecificParams(params);

        if (certificateChain != null)
        {
            X509Util x509Util = new X509Util();
            List<String> x5cStrings = new ArrayList<String>(certificateChain.size());

            for (X509Certificate cert : certificateChain)
            {
               String b64EncodedDer = x509Util.toBase64Der(cert);
               x5cStrings.add(b64EncodedDer);
            }

            params.put(X509_CERTIFICATE_CHAIN_PARAMETER, x5cStrings);
        }

        if (writeOutPrivateKeyToJson)
        {
            fillPrivateTypeSpecificParams(params);
        }
    }

    public PublicKey getPublicKey()
    {
        return (PublicKey) key;
    }

    public void setWriteOutPrivateKeyToJson(boolean writeOutPrivateKeyToJson)
    {
        this.writeOutPrivateKeyToJson = writeOutPrivateKeyToJson;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    public List<X509Certificate> getCertificateChain()
    {
        return certificateChain;
    }

    public X509Certificate getLeafCertificate()
    {
        return (certificateChain != null && !certificateChain.isEmpty()) ? certificateChain.get(0) : null;
    }

    public void setCertificateChain(List<X509Certificate> certificateChain)
    {
        checkForBareKeyCertMismatch();

        this.certificateChain = certificateChain;
    }

    void checkForBareKeyCertMismatch()
    {
        X509Certificate leafCertificate = getLeafCertificate();
        boolean certAndBareKeyMismatch = leafCertificate != null && !leafCertificate.getPublicKey().equals(getPublicKey());
        if (certAndBareKeyMismatch)
        {
            throw new IllegalArgumentException( "The key in the first certificate MUST match the bare public key " +
                "represented by other members of the JWK. Public key = " + getPublicKey() + " cert = " + leafCertificate);
        }
    }

    public void setCertificateChain(X509Certificate... certificates)
    {
        setCertificateChain(Arrays.asList(certificates));
    }

    public static class Factory
    {
        public static PublicJsonWebKey newPublicJwk(Map<String,Object> params) throws JoseException
        {
            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(params);
            return (PublicJsonWebKey) jsonWebKey;
        }

        public static PublicJsonWebKey newPublicJwk(Key publicKey) throws JoseException
        {
            JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(publicKey);
            return (PublicJsonWebKey) jsonWebKey;
        }

        public static PublicJsonWebKey newPublicJwk(String json) throws JoseException
        {
            Map<String, Object> parsed = JsonUtil.parseJson(json);
            return newPublicJwk(parsed);
        }
    }
}
