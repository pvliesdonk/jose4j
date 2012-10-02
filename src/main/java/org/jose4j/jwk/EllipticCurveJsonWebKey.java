package org.jose4j.jwk;

import org.jose4j.keys.BigEndianBigInteger;

import java.util.Map;
import java.math.BigInteger;

/**
 */
public class EllipticCurveJsonWebKey extends JsonWebKey
{
    public static final String ALGORITHM_VALUE = "EC";

    public static final String CURVE_MEMBER_NAME = "crv";

    public static final String X_MEMBER_NAME = "x";
    public static final String Y_MEMBER_NAME = "y";

    private  Map<String, String> params; // TODO  just a temp thing to hold data for parsing tests 

    public EllipticCurveJsonWebKey(Map<String, String> params)
    {
        super(params);

        String curve = params.get(CURVE_MEMBER_NAME);

        String b64x = params.get(X_MEMBER_NAME);
        BigInteger x = BigEndianBigInteger.fromBase64Url(b64x);

        String b64y = params.get(Y_MEMBER_NAME);
        BigInteger y = BigEndianBigInteger.fromBase64Url(b64y);

        //TODO

        this.params = params;
    }
    
    public String getAlgorithm()
    {
        return ALGORITHM_VALUE;
    }

    protected void fillTypeSpecificParams(Map<String, String> params)
    {
        params.putAll(this.params);  // TODO
    }
}
