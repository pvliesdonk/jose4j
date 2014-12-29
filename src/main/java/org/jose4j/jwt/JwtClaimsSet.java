package org.jose4j.jwt;

import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;

import java.util.*;

/**
 *
 */
public class JwtClaimsSet
{
    private Map<String, Object> claimsMap;
    private String rawJson;

    public JwtClaimsSet()
    {
        claimsMap = new LinkedHashMap<>();
    }

    private JwtClaimsSet(String jsonClaims) throws InvalidJwtException
    {
        rawJson = jsonClaims;
        try
        {
            Map<String, Object> parsed = JsonUtil.parseJson(jsonClaims);
            claimsMap = new LinkedHashMap<>(parsed);
        }
        catch (JoseException e)
        {
            throw new InvalidJwtException("Unable to parse JWT Claim Set JSON: " + jsonClaims, e);
        }
    }

    public static JwtClaimsSet parse(String jsonClaims) throws InvalidJwtException
    {
        return new JwtClaimsSet(jsonClaims);
    }

    public String getIssuer() throws MalformedClaimException
    {
        return getClaimValue(ReservedClaimNames.ISSUER, String.class);
    }

    public void setIssuer(String issuer)
    {
        claimsMap.put(ReservedClaimNames.ISSUER, issuer);
    }

    public String getSubject()  throws MalformedClaimException
    {
        return getClaimValue(ReservedClaimNames.SUBJECT, String.class);
    }

    public void setSubject(String subject)
    {
        claimsMap.put(ReservedClaimNames.SUBJECT, subject);
    }

    public void setAudience(String audience)
    {
        claimsMap.put(ReservedClaimNames.AUDIENCE, audience);
    }

    public void setAudience(String... audience)
    {
        setAudience(Arrays.asList(audience));
    }

    public void setAudience(List<String> audiences)
    {
        if (audiences.size() == 1)
        {
            setAudience(audiences.get(0));
        }
        else
        {
            claimsMap.put(ReservedClaimNames.AUDIENCE, audiences);
        }
    }

    public List<String> getAudience() throws MalformedClaimException
    {
        Object audienceObject = claimsMap.get(ReservedClaimNames.AUDIENCE);

        if (audienceObject instanceof String)
        {
            return Collections.singletonList((String) audienceObject);
        }
        else if (audienceObject instanceof List)
        {
            List audienceList = (List) audienceObject;
            String claimName = ReservedClaimNames.AUDIENCE;
            return toStringList(audienceList, claimName);
        }
        else if (audienceObject == null)
        {
            return null;
        }

        throw new MalformedClaimException("The value of the '" + ReservedClaimNames.AUDIENCE + "' claim is not an array of strings or a single string value.");
    }

    private List<String> toStringList(List list, String claimName) throws MalformedClaimException
    {
        if (list == null)
        {
            return null;
        }
        List<String> values = new ArrayList<>();
        for (Object object : list)
        {
            try
            {
                values.add((String) object);
            }
            catch (ClassCastException e)
            {
                throw new MalformedClaimException("The array value of the '" + claimName + "' claim contains non string values " + classCastMsg(e, object), e);
            }
        }
        return values;
    }

    public IntDate getExpirationTime() throws MalformedClaimException
    {
        return getIntDateClaimValue(ReservedClaimNames.EXPIRATION_TIME);
    }

    public void setExpirationTime(IntDate expirationTime)
    {
        setIntDateClaim(ReservedClaimNames.EXPIRATION_TIME, expirationTime);
    }

    public void setExpirationTimeMinutesInTheFuture(float minutes)
    {
        setExpirationTime(offsetFromNow(minutes));
    }

    private IntDate offsetFromNow(float offsetMinutes)
    {
        final IntDate intDate = IntDate.now();
        float secondsOffset = offsetMinutes * 60;
        intDate.addSeconds((long)secondsOffset);
        return intDate;
    }

    public IntDate getNotBefore() throws MalformedClaimException
    {
        return getIntDateClaimValue(ReservedClaimNames.NOT_BEFORE);
    }

    public void setNotBefore(IntDate notBefore)
    {
        setIntDateClaim(ReservedClaimNames.NOT_BEFORE, notBefore);
    }

    public void setNotBeforeMinutesInThePast(float minutes)
    {
        setNotBefore(offsetFromNow(-1 * minutes));
    }

    public IntDate getIssuedAt() throws MalformedClaimException
    {
        return getIntDateClaimValue(ReservedClaimNames.ISSUED_AT);
    }

    public void setIssuedAt(IntDate issuedAt)
    {
        setIntDateClaim(ReservedClaimNames.ISSUED_AT, issuedAt);
    }

    public void setIssuedAtToNow()
    {
        setIssuedAt(IntDate.now());
    }

    public String getJwtId() throws MalformedClaimException
    {
        return getClaimValue(ReservedClaimNames.JWT_ID, String.class);
    }

    public void setJwtId(String jwtId)
    {
        claimsMap.put(ReservedClaimNames.JWT_ID, jwtId);
    }

    public void setGeneratedJwtId(int numberOfBytes)
    {
        byte[] rndbytes = ByteUtil.randomBytes(numberOfBytes);
        String jti = Base64Url.encode(rndbytes);
        setJwtId(jti);
    }

    public void setGeneratedJwtId()
    {
        setGeneratedJwtId(16);
    }

    public void unsetClaim(String claimName)
    {
        claimsMap.remove(claimName);
    }

    public <T> T getClaimValue(String claimName, Class<T> type) throws MalformedClaimException
    {
        Object o = claimsMap.get(claimName);
        try
        {
            return type.cast(o);
        }
        catch (ClassCastException e)
        {
            throw new MalformedClaimException("The value of the '" + claimName + "' claim is not the expected type " + classCastMsg(e, o), e);
        }
    }

    private String classCastMsg(ClassCastException e, Object o)
    {
        return "(" + o + " - " +e.getMessage() + ")";
    }

    public IntDate getIntDateClaimValue(String claimName) throws MalformedClaimException
    {
        Number number = getClaimValue(claimName, Number.class);
        return number != null ? IntDate.fromSeconds(number.longValue()) : null;
    }

    public String getStringClaimValue(String claimName) throws MalformedClaimException
    {
        return getClaimValue(claimName, String.class);
    }

    public List<String> getStringListClaimValue(String claimName) throws MalformedClaimException
    {
        List listClaimValue = getClaimValue(claimName, List.class);
        return toStringList(listClaimValue, claimName);
    }

    public void setIntDateClaim(String claimName, IntDate value)
    {
        claimsMap.put(claimName, value != null ? value.getValue() : null);
    }

    public void setStringClaim(String claimName, String value)
    {
        claimsMap.put(claimName, value);
    }

    public void setStringListClaim(String claimName, List<String> values)
    {
        claimsMap.put(claimName, values);
    }

    public void setStringListClaim(String claimName, String... values)
    {
        claimsMap.put(claimName, Arrays.asList(values));
    }

    public void setClaim(String claimName, Object value)
    {
        claimsMap.put(claimName, value);
    }

    public boolean isClaimValueOfType(String claimName, Class type)
    {
        try
        {
            return getClaimValue(claimName, type) != null;
        }
        catch (MalformedClaimException e)
        {
            return false;
        }
    }

    public boolean isClaimValueString(String claimName)
    {
        return isClaimValueOfType(claimName, String.class);
    }

    public boolean isClaimValueStringList(String claimName)
    {
        try
        {
            return getStringListClaimValue(claimName) != null;
        }
        catch (MalformedClaimException e)
        {
            return false;
        }
    }

    public Map<String,List<Object>> flattenClaims()
    {
        return flattenClaims(null);
    }

    public Map<String,List<Object>> flattenClaims(Set<String> omittedClaims)
    {
        omittedClaims = omittedClaims == null ? Collections.<String>emptySet() : omittedClaims;
        Map<String,List<Object>> flattenedClaims = new LinkedHashMap<>();
        for (Map.Entry<String,Object> e : claimsMap.entrySet())
        {
            final String key = e.getKey();
            if (!omittedClaims.contains(key))
            {
                dfs(null, key, e.getValue(), flattenedClaims);
            }
        }
        return flattenedClaims;
    }

    private void dfs(String baseName, String name, Object value, Map<String,List<Object>> flattenedClaims)
    {
        String key = (baseName == null ? "" : baseName + ".") + name;
        if (value instanceof List)
        {
            List<Object> newList = new ArrayList<>();
            for (Object item : (List)value)
            {
                if (item instanceof Map)
                {
                    Map<?,?> mv = (Map<?,?>) item;
                    for (Map.Entry<?,?> e : mv.entrySet())
                    {
                        dfs(key, e.getKey().toString(), e.getValue(), flattenedClaims);
                    }
                }
                else
                {
                    newList.add(item);
                }
            }
            flattenedClaims.put(key, newList);
        }
        else if (value instanceof Map)
        {
            Map<?,?> mapValue = (Map<?,?>) value;
            for (Map.Entry<?,?> e : mapValue.entrySet())
            {
                dfs(key, e.getKey().toString(), e.getValue(), flattenedClaims);
            }
        }
        else
        {
            flattenedClaims.put(key, Collections.singletonList(value));
        }
    }


    public Map<String, Object> getClaimsMap(Set<String> omittedClaims)
    {
        omittedClaims = (omittedClaims != null) ? omittedClaims : Collections.<String>emptySet();
        LinkedHashMap<String, Object>  claims = new LinkedHashMap<>(claimsMap);
        for (String omittedClaim : omittedClaims)
        {
            claims.remove(omittedClaim);
        }

        return claims;
    }

    public Map<String, Object> getClaimsMap()
    {
        return getClaimsMap(null);
    }

    public Collection<String> getClaimNames(Set<String> omittedClaims)
    {
        return getClaimsMap(omittedClaims).keySet();
    }

    public Collection<String> getClaimNames()
    {
        return getClaimNames(null);
    }

    public String toJson()
    {
        return JsonUtil.toJson(claimsMap);
    }

    public String getRawJson()
    {
        return rawJson;
    }
}
