package org.jose4j.jwt.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwx.JsonWebStructure;
import org.junit.Assert;

import java.util.Collections;

/**
 *
 */
public class SimpleJwtConsumerTestHelp
{
    static Log log = LogFactory.getLog(SimpleJwtConsumerTestHelp.class);

    static void expectProcessingFailure(String jwt, JwtConsumer jwtConsumer)
    {
        try
        {
            jwtConsumer.process(jwt);
            Assert.fail("jwt process/validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            log.debug("Expected exception: " + e);
        }
    }

    static void goodValidate(JwtClaimsSet jwtClaimsSet, JwtConsumer jwtConsumer) throws InvalidJwtException
    {
        jwtConsumer.validate(new JwtContext(jwtClaimsSet, Collections.<JsonWebStructure>emptyList()));
    }

    static void expectValidationFailure(JwtClaimsSet jwtClaimsSet, JwtConsumer jwtConsumer)
    {
        try
        {
            jwtConsumer.validate(new JwtContext(jwtClaimsSet, Collections.<JsonWebStructure>emptyList()));
            Assert.fail("claims validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            log.debug("Expected exception: " + e);
        }
    }
}
