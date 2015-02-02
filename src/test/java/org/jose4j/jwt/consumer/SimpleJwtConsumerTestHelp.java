/*
 * Copyright 2012-2015 Brian Campbell
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
package org.jose4j.jwt.consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwt.JwtClaims;
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

    static void goodValidate(JwtClaims jwtClaims, JwtConsumer jwtConsumer) throws InvalidJwtException
    {
        jwtConsumer.validate(new JwtContext(jwtClaims, Collections.<JsonWebStructure>emptyList()));
    }

    static void expectValidationFailure(JwtClaims jwtClaims, JwtConsumer jwtConsumer)
    {
        try
        {
            jwtConsumer.validate(new JwtContext(jwtClaims, Collections.<JsonWebStructure>emptyList()));
            Assert.fail("claims validation should have thrown an exception");
        }
        catch (InvalidJwtException e)
        {
            log.debug("Expected exception: " + e);
        }
    }
}
