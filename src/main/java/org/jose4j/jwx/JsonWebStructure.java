package org.jose4j.jwx;

import org.jose4j.json.JsonHeaderUtil;

import java.util.LinkedHashMap;
import java.util.Map;
import java.security.Key;

/**
 */
public abstract class JsonWebStructure
{    
    private Map<String,String> headerMap = new LinkedHashMap<String,String>();
    private String header;

    private byte[] integrity;

    private Key key;

    abstract public String getCompactSerialization();

    public String getHeader()
    {
        if (header == null)
        {
            header = JsonHeaderUtil.toJson(headerMap);
        }
        return header;
    }

    public void setHeader(String name, String value)
    {
        headerMap.put(name, value);
        this.header = null;
    }

    public void setHeaderAsString(String header)
    {
        this.header = header;
        headerMap = JsonHeaderUtil.parseJson(header);
    }

    public String getHeader(String name)
    {
        return headerMap.get(name);
    }

    public void setAlgorithmHeaderValue(String alg)
    {
        setHeader(HeaderParameterNames.ALGORITHM, alg);
    }

    public String getAlgorithmHeaderValue()
    {
        return getHeader(HeaderParameterNames.ALGORITHM);
    }

    public void setKeyIdHeaderValue(String kid)
    {
        setHeader(HeaderParameterNames.KEY_ID, kid);
    }

    public String getKeyIdHeaderValue()
    {
        return getHeader(HeaderParameterNames.KEY_ID);
    }

    public Key getKey()
    {
        return key;
    }

    public void setKey(Key key)
    {
        this.key = key;
    }

    protected byte[] getIntegrity()
    {
        return integrity;
    }

    protected void setIntegrity(byte[] integrity)
    {
        this.integrity = integrity;
    }
}
