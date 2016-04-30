/*
 * Copyright 2012-2016 Brian Campbell
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
package org.jose4j.keys.resolvers;

import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.ExceptionHelp;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UncheckedJoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT;
import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT;

/**
 *
 */
public class X509VerificationKeyResolver implements VerificationKeyResolver
{
    private static final Logger log = LoggerFactory.getLogger(X509VerificationKeyResolver.class);

    private Map<String,X509Certificate> x5tMap;
    private Map<String,X509Certificate> x5tS256Map;

    private boolean tryAllOnNoThumbHeader;

    public X509VerificationKeyResolver(List<X509Certificate> certificates)
    {
        x5tMap = new LinkedHashMap<>();
        x5tS256Map = new LinkedHashMap<>();

        for (X509Certificate cert : certificates)
        {
            try
            {
                String x5t = X509Util.x5t(cert);
                x5tMap.put(x5t, cert);

                String x5tS256 = X509Util.x5tS256(cert);
                x5tS256Map.put(x5tS256, cert);
            }
            catch (UncheckedJoseException e)
            {
                log.warn("Unable to get certificate thumbprint.", e);
            }
        }
    }

    public X509VerificationKeyResolver(X509Certificate... certificates)
    {
        this(Arrays.asList(certificates));
    }

    public void setTryAllOnNoThumbHeader(boolean tryAllOnNoThumbHeader)
    {
        this.tryAllOnNoThumbHeader = tryAllOnNoThumbHeader;
    }

    @Override
    public Key resolveKey(JsonWebSignature jws, List<JsonWebStructure> nestingContext) throws UnresolvableKeyException
    {
        String x5t = jws.getX509CertSha1ThumbprintHeaderValue();
        String x5tS256 = jws.getX509CertSha256ThumbprintHeaderValue();

        if (x5t == null && x5tS256 == null)
        {
            if (tryAllOnNoThumbHeader)
            {
                return attemptAll(jws);
            }
            throw new UnresolvableKeyException("Neither the " + X509_CERTIFICATE_THUMBPRINT + " header nor the " + X509_CERTIFICATE_SHA256_THUMBPRINT + " header are present in the JWS.");
        }

        X509Certificate x509Certificate = x5tMap.get(x5t);
        if (x509Certificate == null)
        {
            x509Certificate = x5tS256Map.get(x5tS256);
        }

        if (x509Certificate == null)
        {
            StringBuilder sb = new StringBuilder();

            sb.append("The X.509 Certificate Thumbprint header(s) in the JWS do not identify any of the provided Certificates -");
            if (x5t != null)
            {
                sb.append(" ").append(X509_CERTIFICATE_THUMBPRINT).append("=").append(x5t);
                sb.append(" vs. SHA-1 thumbs:").append(x5tMap.keySet());
            }

            if (x5tS256 != null)
            {
                sb.append(" ").append(X509_CERTIFICATE_SHA256_THUMBPRINT).append("=").append(x5tS256);
                sb.append(" vs. SHA-256 thumbs:").append(x5tS256Map.keySet());
            }

            sb.append(".");
            throw new UnresolvableKeyException(sb.toString());
        }

        return x509Certificate.getPublicKey();
    }

    private Key attemptAll(JsonWebSignature jws) throws UnresolvableKeyException
    {
        for (X509Certificate certificate : x5tMap.values())
        {
            PublicKey publicKey = certificate.getPublicKey();
            jws.setKey(publicKey);

            try
            {
                if (jws.verifySignature())
                {
                    return publicKey;
                }
            }
            catch (JoseException e)
            {
                log.debug("Verify signature didn't work: {}", ExceptionHelp.toStringWithCauses(e));
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Unable to verify the signature with any of the provided keys - SHA-1 thumbs of provided certificates: ");
        sb.append(x5tMap.keySet());
        sb.append(".");
        throw new UnresolvableKeyException(sb.toString());
    }
}
