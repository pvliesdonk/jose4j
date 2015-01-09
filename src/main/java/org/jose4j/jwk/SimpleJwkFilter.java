package org.jose4j.jwk;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class SimpleJwkFilter
{
    public static boolean OMITTED_OKAY = true;
    public static boolean VALUE_REQUIRED = false;

    private static final String[] EMPTY = new String[2];
    private Criteria kid;
    private Criteria kty;
    private Criteria use;
    private Criteria alg;
    private Criteria x5t;
    private Criteria x5tS256;
    private boolean allowThumbsFallbackDeriveFromX5c;

    private Criteria crv;

    public void setKid(String expectedKid, boolean omittedValueAcceptable)
    {
        kid = new Criteria(expectedKid, omittedValueAcceptable);
    }

    public void setKty(String expectedKty)
    {
        kty = new Criteria(expectedKty, false);
    }

    public void setUse(String expectedUse, boolean omittedValueAcceptable)
    {
        use = new Criteria(expectedUse, omittedValueAcceptable);
    }

    public void setAlg(String expectedAlg, boolean omittedValueAcceptable)
    {
        alg = new Criteria(expectedAlg, omittedValueAcceptable);
    }

    public void setX5t(String expectedThumb, boolean omittedValueAcceptable)
    {
        x5t = new Criteria(expectedThumb, omittedValueAcceptable);
    }

    public void setX5tS256(String expectedThumb, boolean omittedValueAcceptable)
    {
        x5tS256 = new Criteria(expectedThumb, omittedValueAcceptable);
    }

    public void setAllowFallbackDeriveFromX5cForX5Thumbs(boolean allow)
    {
        this.allowThumbsFallbackDeriveFromX5c = allow;
    }

    public void setCrv(String expectedCrv, boolean omittedValueAcceptable)
    {
        this.crv = new Criteria(expectedCrv, omittedValueAcceptable);
    }

    public List<JsonWebKey> filter(Collection<JsonWebKey> jsonWebKeys)
    {
        List<JsonWebKey> filtered = new LinkedList<>();
        for (JsonWebKey jwk : jsonWebKeys)
        {
            boolean match = isMatch(kid, jwk.getKeyId());
            match &= isMatch(kty, jwk.getKeyType());
            match &= isMatch(use, jwk.getUse());
            match &= isMatch(alg, jwk.getAlgorithm());
            String[] thumbs = getThumbs(jwk, allowThumbsFallbackDeriveFromX5c);
            match &= isMatch(x5t, thumbs[0]);
            match &= isMatch(x5tS256, thumbs[1]);
            match &= isMatch(crv, getCrv(jwk));

            if (match)
            {
                filtered.add(jwk);
            }
        }
        return filtered;
    }

    boolean isMatch(Criteria criteria, String value)
    {
        return (criteria == null) || criteria.meetsCriteria(value);
    }

    String getCrv(JsonWebKey jwk)
    {
        try
        {
            return ((EllipticCurveJsonWebKey) jwk).getCurveName();
        }
        catch (ClassCastException e)
        {
            return null;
        }
    }


    String[] getThumbs(JsonWebKey jwk, boolean allowFallbackDeriveFromX5c) // todo
    {
        if (x5t == null && x5tS256 == null)
        {
            return EMPTY;
        }

        try
        {
            PublicJsonWebKey publicJwk = (PublicJsonWebKey) jwk;
            String x5t = publicJwk.getX509CertificateSha1Thumbprint(allowFallbackDeriveFromX5c);
            String x5tS256 = publicJwk.getX509CertificateSha256Thumbprint(allowFallbackDeriveFromX5c);

            return new String[] {x5t, x5tS256};
        }
        catch (ClassCastException e)
        {
            return EMPTY;
        }
    }

    private static class Criteria
    {
        String value;
        boolean noValueOk;

        private Criteria(String value, boolean noValueOk)
        {
            this.value = value;
            this.noValueOk = noValueOk;
        }

        public boolean meetsCriteria(String value)
        {
            if (value == null)
            {
                return noValueOk;
            }
            else
            {
                return value.equals(this.value);
            }
        }
    }
}
