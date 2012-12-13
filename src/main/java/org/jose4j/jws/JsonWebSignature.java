/*
 * Copyright 2012 Brian Campbell
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

package org.jose4j.jws;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwx.CompactSerialization;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.KeyType;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

import java.security.Key;

/**
 */
public class JsonWebSignature extends JsonWebStructure
{
    public static final short COMPACT_SERIALIZATION_PARTS = 3;

    private Base64Url base64url = new Base64Url();

    private String payload;
    private String payloadCharEncoding = StringUtil.UTF_8;

    public void setPayload(String payload)
    {
        this.payload = payload;
    }

    public void setCompactSerialization(String compactSerialization) throws JoseException
    {
        String[] parts = CompactSerialization.deserialize(compactSerialization);
        if (parts.length != COMPACT_SERIALIZATION_PARTS)
        {
            throw new JoseException("A JWS Compact Serialization must have exactly 3 parts separated by period ('.') characters");
        }

        setHeaderAsString(base64url.base64UrlDecodeToUtf8String(parts[0]));
        payload = base64url.base64UrlDecodeToString(parts[1], payloadCharEncoding);
        setSignature(base64url.base64UrlDecode(parts[2]));
    }

    public String getCompactSerialization() throws JoseException
    {
        this.sign();
        return CompactSerialization.serialize(getSecuredInput(), getEncodedSignature());
    }

    private void sign() throws JoseException
    {
        JsonWebSignatureAlgorithm algorithm = getAlgorithm();
        Key signingKey = getKey();
        algorithm.validateSigningKey(signingKey);
        byte[] inputBytes = getSecuredInputBytes();
        byte[] signatureBytes = algorithm.sign(signingKey, inputBytes);
        setSignature(signatureBytes);
    }

    public boolean verifySignature() throws JoseException
    {
        JsonWebSignatureAlgorithm algorithm = getAlgorithm();
        Key verificationKey = getKey();
        algorithm.validateVerificationKey(verificationKey);
        byte[] signatureBytes = getSignature();
        byte[] inputBytes = getSecuredInputBytes();
        return algorithm.verifySignature(signatureBytes, verificationKey, inputBytes);
    }

    private JsonWebSignatureAlgorithm getAlgorithm() throws JoseException
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new JoseException(HeaderParameterNames.ALGORITHM + " header not set.");
        }

        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = factoryFactory.getJwsAlgorithmFactory();
        return jwsAlgorithmFactory.getAlgorithm(algo);
    }

    private byte[] getSecuredInputBytes() throws JoseException
    {
        String securedInput = getSecuredInput();
        return StringUtil.getBytesUtf8(securedInput);
    }

    private String getSecuredInput() throws JoseException
    {
        return CompactSerialization.serialize(getEncodedHeader(), getEncodedPayload());
    }

    private String getEncodedHeader()
    {
        return base64url.base64UrlEncodeUtf8ByteRepresentation(getHeader());
    }

    public String getPayload()
    {
        return payload;
    }

    public String getPayloadCharEncoding()
    {
        return payloadCharEncoding;
    }

    public void setPayloadCharEncoding(String payloadCharEncoding)
    {
        this.payloadCharEncoding = payloadCharEncoding;
    }

    public KeyType getKeyType() throws JoseException
    {
        return getAlgorithm().getKeyType();
    }

    private String getEncodedPayload()
    {
        return base64url.base64UrlEncode(payload, payloadCharEncoding);
    }

    private String getEncodedSignature()
    {
        return base64url.base64UrlEncode(getSignature());
    }

    protected byte[] getSignature()
    {
        return getIntegrity();
    }

    protected void setSignature(byte[] signature)
    {
        setIntegrity(signature);
    }
}
