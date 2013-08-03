package org.jose4j.jwx;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonHeaderUtil;
import org.jose4j.lang.JoseException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 */
public class Headers
{
    protected Base64Url base64url = new Base64Url();

    private Map<String, String> headerMap = new LinkedHashMap<String, String>();
    private String header;
    private String encodedHeader;

    public String getHeaderAsString()
    {
        if (header == null)
        {
            header = JsonHeaderUtil.toJson(headerMap);
        }
        return header;
    }

    String getEncodedHeader()
    {
        if (encodedHeader == null)
        {
            String headerAsString = getHeaderAsString();
            encodedHeader = base64url.base64UrlEncodeUtf8ByteRepresentation(headerAsString);
        }
        return encodedHeader;
    }

    public void setHeaderValue(String name, String value)
    {
        headerMap.put(name, value);
        this.header = null;
    }

    public String getHeaderValue(String headerName)
    {
        return headerMap.get(headerName);
    }

    public void setHeaderAsString(String header) throws JoseException
    {
        this.header = header;
        headerMap = JsonHeaderUtil.parseJson(header);
    }

    void setEncodedHeader(String encodedHeader) throws JoseException
    {
        this.encodedHeader = encodedHeader;
        setHeaderAsString(base64url.base64UrlDecodeToUtf8String(this.encodedHeader));
    }
}
