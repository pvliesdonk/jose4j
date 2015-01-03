package org.jose4j.jws;

import org.hamcrest.CoreMatchers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.ByteUtil;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 */
public class ChangingKeyTest
{
    @Test
    public void testOnNewKey() throws Exception
    {
        JsonWebKey jwk = JsonWebKey.Factory.newJwk("{\"kty\":\"oct\",\"k\":\"9el2Km2s5LHVQqUCWIdvwMsclQqQc6CwObMnCpCC8jY\"}");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization("eyJhbGciOiJIUzI1NiJ9.c2lnaA.2yUt5UtfsRK1pnN0KTTv7gzHTxwDqDz2OkFSqlbQ40A");
        jws.setKey(new HmacKey(new byte[32]));
        Assert.assertThat(false, CoreMatchers.equalTo(jws.verifySignature()));

        // sigh, setting a new key should now clear the little internal signature result cache...
        jws.setKey(jwk.getKey());
        Assert.assertThat(true, CoreMatchers.equalTo(jws.verifySignature()));

        jws.setKey(new HmacKey(ByteUtil.randomBytes(32)));
        Assert.assertThat(false, CoreMatchers.equalTo(jws.verifySignature()));

        jws.setKey(null);
        try
        {
            jws.verifySignature();
        }
        catch (JoseException e)
        {
            // expected
        }
    }
}
