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

package org.jose4j.jwx;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.Algorithm;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.X509Util;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT;
import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT;

/**
 */
public abstract class JsonWebStructure
{
    protected Base64Url base64url = new Base64Url();

    protected Headers headers = new Headers();

    private byte[] integrity;

    private Key key;

    protected boolean doKeyValidation = true;

    protected String rawCompactSerialization;

    private AlgorithmConstraints algorithmConstraints = AlgorithmConstraints.NO_CONSTRAINTS;

    private Set<String> knownCriticalHeaders = Collections.emptySet();

    private static final ProviderContext DEFAULT_PROVIDER_CONTEXT = new ProviderContext();
    private ProviderContext providerCtx = DEFAULT_PROVIDER_CONTEXT;

    abstract public String getCompactSerialization() throws JoseException;
    abstract protected void setCompactSerializationParts(String[] parts) throws JoseException;

    abstract public String getPayload() throws JoseException;
    abstract public void setPayload(String payload);

    abstract public Algorithm getAlgorithm() throws InvalidAlgorithmException;

    public static JsonWebStructure fromCompactSerialization(String cs) throws JoseException
    {
        JsonWebStructure jsonWebObject;
        String[] parts = CompactSerializer.deserialize(cs);
        if (parts.length == JsonWebEncryption.COMPACT_SERIALIZATION_PARTS)
        {
            jsonWebObject = new JsonWebEncryption();
        }
        else if (parts.length == JsonWebSignature.COMPACT_SERIALIZATION_PARTS)
        {
            jsonWebObject = new JsonWebSignature();
        }
        else
        {
            throw new JoseException("Invalid JOSE Compact Serialization. Expecting either "
                    + JsonWebSignature.COMPACT_SERIALIZATION_PARTS + " or "
                    + JsonWebEncryption.COMPACT_SERIALIZATION_PARTS
                    + " parts for JWS or JWE respectively but was " + parts.length + ".");
        }

        jsonWebObject.setCompactSerializationParts(parts);
        jsonWebObject.rawCompactSerialization = cs;
        return jsonWebObject;
    }

    public void setCompactSerialization(String compactSerialization) throws JoseException
    {
    	String[] parts = CompactSerializer.deserialize(compactSerialization);
        setCompactSerializationParts(parts);
        rawCompactSerialization = compactSerialization;
    }

    /**
     * @deprecated replaced by {@link #getHeaders()} and {@link org.jose4j.jwx.Headers#getFullHeaderAsJsonString()}
     */
    public String getHeader()
    {
        return getHeaders().getFullHeaderAsJsonString();
    }

    protected String getEncodedHeader()
    {
        return headers.getEncodedHeader();
    }

    public void setHeader(String name, String value)
    {
        headers.setStringHeaderValue(name, value);
    }

    protected void setEncodedHeader(String encodedHeader) throws JoseException
    {
        checkNotEmptyPart(encodedHeader, "Encoded Header");
        headers.setEncodedHeader(encodedHeader);
    }

    public Headers getHeaders()
    {
        return headers;
    }

    protected void checkNotEmptyPart(String encodedPart, String partName) throws JoseException
    {
        if (encodedPart == null || encodedPart.length() == 0)
        {
            throw new JoseException("The "+ partName +" cannot be empty.");
        }
    }

    public String getHeader(String name)
    {
        return headers.getStringHeaderValue(name);
    }

    public void setAlgorithmHeaderValue(String alg)
    {
        setHeader(HeaderParameterNames.ALGORITHM, alg);
    }

    public String getAlgorithmHeaderValue()
    {
        return getHeader(HeaderParameterNames.ALGORITHM);
    }

    public void setContentTypeHeaderValue(String cty)
    {
        setHeader(HeaderParameterNames.CONTENT_TYPE, cty);
    }

    public String getContentTypeHeaderValue()
    {
        return getHeader(HeaderParameterNames.CONTENT_TYPE);
    }

    public void setKeyIdHeaderValue(String kid)
    {
        setHeader(HeaderParameterNames.KEY_ID, kid);
    }

    public String getKeyIdHeaderValue()
    {
        return getHeader(HeaderParameterNames.KEY_ID);
    }

    public String getX509CertSha1ThumbprintHeaderValue()
    {
        return getHeader(X509_CERTIFICATE_THUMBPRINT);
    }

    public void setX509CertSha1ThumbprintHeaderValue(String x5t)
    {
        setHeader(X509_CERTIFICATE_THUMBPRINT, x5t);
    }

    public void setX509CertSha1ThumbprintHeaderValue(X509Certificate certificate)
    {
        String x5t = X509Util.x5t(certificate);
        setX509CertSha1ThumbprintHeaderValue(x5t);
    }

    public String getX509CertSha256ThumbprintHeaderValue()
    {
        return getHeader(X509_CERTIFICATE_SHA256_THUMBPRINT);
    }

    public void setX509CertSha256ThumbprintHeaderValue(String x5tS256)
    {
        setHeader(X509_CERTIFICATE_SHA256_THUMBPRINT, x5tS256);
    }

    public void setX509CertSha256ThumbprintHeaderValue(X509Certificate certificate)
    {
        String x5tS256 = X509Util.x5tS256(certificate);
        setX509CertSha256ThumbprintHeaderValue(x5tS256);
    }

    public Key getKey()
    {
        return key;
    }

    public void setKey(Key key)
    {
        boolean same = (key == null ? this.key == null : key.equals(this.key));
        if (!same)
        {
            onNewKey();
        }

        this.key = key;
    }

    protected void onNewKey()
    {
        // just a hook that subclasses can override
    }

    protected byte[] getIntegrity()
    {
        return integrity;
    }

    protected void setIntegrity(byte[] integrity)
    {
        this.integrity = integrity;
    }

    public boolean isDoKeyValidation()
    {
        return doKeyValidation;
    }

    public void setDoKeyValidation(boolean doKeyValidation)
    {
        this.doKeyValidation = doKeyValidation;
    }

    protected AlgorithmConstraints getAlgorithmConstraints()
    {
        return algorithmConstraints;
    }

    public void setAlgorithmConstraints(AlgorithmConstraints algorithmConstraints)
    {
        this.algorithmConstraints = algorithmConstraints;
    }

    /**
     * Sets the value(s) of the critical ("crit") header, defined in
     * <a href="http://tools.ietf.org/html/rfc7515#section-4.1.11">section 4.1.11 of RFC 7515</a>,
     * which indicates that those headers MUST be understood and processed by the recipient.
     * @param headerNames the name(s) of headers that will be marked as critical
     */
    public void setCriticalHeaderNames(String... headerNames)
    {
        headers.setObjectHeaderValue(HeaderParameterNames.CRITICAL, headerNames);
    }

    /**
     * Sets the values of the critical ("crit") header that are acceptable for the library to process.
     * Basically calling this  is telling the jose4j library to allow these headers marked as critical
     * and saying that the caller knows how to process them and will do so.
     * @param knownCriticalHeaders one or more header names that will be allowed as values of the critical header
     */
    public void setKnownCriticalHeaders(String... knownCriticalHeaders)
    {
        this.knownCriticalHeaders = new HashSet<>(Arrays.asList(knownCriticalHeaders));
    }

    protected void checkCrit() throws JoseException
    {
        final Object criticalHeaderObjectValue = headers.getObjectHeaderValue(HeaderParameterNames.CRITICAL);
        if (criticalHeaderObjectValue != null)
        {
            try
            {
                for (String criticalHeader : (List<String>) criticalHeaderObjectValue)
                {
                    if (!knownCriticalHeaders.contains(criticalHeader))
                    {
                        throw new JoseException("Unrecognized header '" + criticalHeader + "' marked as critical.");
                    }
                }
            }
            catch (ClassCastException e)
            {
                throw new JoseException(HeaderParameterNames.CRITICAL + " header value not an array.");
            }
        }
    }


    protected ProviderContext getProviderCtx()
    {
        return providerCtx;
    }

    /**
     * Sets the {@link ProviderContext} for this JWS or JWE, which allows for
     * a particular Java Cryptography Architecture provider to be indicated by name to be used
     * for various cryptographic operations. A {@code SecureRandom} source of randomness can also be
     * supplied.
     *
     * @param providerCtx the ProviderContext object indicating the Java Cryptography Architecture provider
     * to be used for various cryptographic operations.
     */
    public void setProviderContext(ProviderContext providerCtx)
    {
        this.providerCtx = providerCtx;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName()).append(getHeaders().getFullHeaderAsJsonString());
        if (rawCompactSerialization != null)
        {
            sb.append("->").append(rawCompactSerialization);
        }
        return sb.toString();
    }
}
