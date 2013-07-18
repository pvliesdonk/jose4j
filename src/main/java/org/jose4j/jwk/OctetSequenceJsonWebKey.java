package org.jose4j.jwk;

import org.jose4j.base64url.Base64Url;
import org.jose4j.lang.JsonHelp;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Map;

/**
 */
public class OctetSequenceJsonWebKey extends JsonWebKey
{
    public static final String KEY_TYPE = "oct";
    public static final String KEY_VALUE_MEMBER_NAME = "k";

    public OctetSequenceJsonWebKey(Key key)
    {
        super(key);
    }

    public OctetSequenceJsonWebKey(Map<String, Object> params)
    {
        super(params);
        Base64Url base64Url = new Base64Url();
        String b64KeyBytes = JsonHelp.getString(params, KEY_VALUE_MEMBER_NAME);
        byte[] bytes = base64Url.base64UrlDecode(b64KeyBytes);
        key = new SecretKeySpec(bytes, null); // um... how could I know the alg?
    }

    @Override
    public String getKeyType()
    {
        return KEY_TYPE;
    }

    @Override
    protected void fillTypeSpecificParams(Map<String, Object> params)
    {
        Base64Url base64Url = new Base64Url();
        byte[] keyBytes = key.getEncoded();
        String encodedBytes = base64Url.base64UrlEncode(keyBytes);
        params.put(KEY_VALUE_MEMBER_NAME, encodedBytes);
    }
}
