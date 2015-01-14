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

import org.jose4j.base64url.Base64;
import org.jose4j.base64url.Base64Url;
import org.jose4j.base64url.SimplePEMEncoder;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;

/**
 */
public class X509Util
{
    private static final String FACTORY_TYPE = "X.509";

    private CertificateFactory certFactory;


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

    public String toBase64(X509Certificate x509Certificate)
    {
        try
        {
            byte[] der = x509Certificate.getEncoded();
            return Base64.encode(der);
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalStateException("Unexpected problem getting encoded certificate.", e);
        }
    }

    public String toPem(X509Certificate x509Certificate)
    {
        try
        {
            byte[] der = x509Certificate.getEncoded();
            return SimplePEMEncoder.encode(der);
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalStateException("Unexpected problem getting encoded certificate.", e);
        }
    }

    public X509Certificate fromBase64Der(String b64EncodedDer) throws JoseException
    {
        byte[] der = Base64.decode(b64EncodedDer);
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

    public static String x5t(X509Certificate certificate)
    {
        return base64urlThumbprint(certificate, "SHA-1");
    }

    public static String x5tS256(X509Certificate certificate)
    {
        return base64urlThumbprint(certificate, "SHA-256");
    }

    private static String base64urlThumbprint(X509Certificate certificate, String hashAlg)
    {
        MessageDigest msgDigest = getMessageDigest(hashAlg);
        byte[] certificateEncoded;
        try
        {
            certificateEncoded = certificate.getEncoded();
        }
        catch (CertificateEncodingException e)
        {
            throw new UncheckedJoseException("Unable to get certificate thumbprint due to unexpected certificate encoding exception.", e);
        }
        byte[] digest = msgDigest.digest(certificateEncoded);
        return Base64Url.encode(digest);
    }

    private static MessageDigest getMessageDigest(String alg)
    {
        try
        {
            return MessageDigest.getInstance(alg);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new UncheckedJoseException("Unable to get MessageDigest instance with " + alg);
        }
    }
}
