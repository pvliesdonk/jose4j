package org.jose4j.jws;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwx.CompactSerialization;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.StringUtil;
import org.jose4j.keys.KeyType;

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

    public void setCompactSerialization(String compactSerialization)
    {
        String[] parts = CompactSerialization.deserialize(compactSerialization);
        if (parts.length != COMPACT_SERIALIZATION_PARTS)
        {
            throw new IllegalArgumentException("A JWS Compact Serialization must have exactly 3 parts separated by period ('.') characters");
        }

        setHeaderAsString(base64url.base64UrlDecodeToUtf8String(parts[0]));
        payload = base64url.base64UrlDecodeToString(parts[1], payloadCharEncoding);
        setSignature(base64url.base64UrlDecode(parts[2]));
    }

    public String getCompactSerialization()
    {
        this.sign();
        return CompactSerialization.serialize(getSecuredInput(), getEncodedSignature());
    }

    private void sign()
    {
        JsonWebSignatureAlgorithm algorithm = getAlgorithm();
        byte[] inputBytes = getSecuredInputBytes();
        byte[] signatureBytes = algorithm.sign(getKey(), inputBytes);
        setSignature(signatureBytes);
    }

    public boolean verifySignature()
    {
        JsonWebSignatureAlgorithm algorithm = getAlgorithm();
        byte[] signatureBytes = getSignature();
        byte[] inputBytes = getSecuredInputBytes();
        return algorithm.verifySignature(signatureBytes, getKey(), inputBytes);
    }

    private JsonWebSignatureAlgorithm getAlgorithm()
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new IllegalStateException(HeaderParameterNames.ALGORITHM + " header not set.");    
        }

        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = factoryFactory.getJwsAlgorithmFactory();
        return jwsAlgorithmFactory.getAlgorithm(algo);
    }

    private byte[] getSecuredInputBytes()
    {
        String securedInput = getSecuredInput();
        return StringUtil.getBytesUtf8(securedInput);
    }

    private String getSecuredInput()
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

    public KeyType getKeyType()
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
