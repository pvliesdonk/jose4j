/*
 * Copyright 2012-2016 Brian Campbell
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
package org.jose4j.jwk;

import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.junit.Test;

import java.security.Key;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.jose4j.jwk.JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC;
import static org.jose4j.jwk.JsonWebKey.OutputControlLevel.PUBLIC_ONLY;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class ExtraJwkParametersTest
{
    @Test
    public void parseWithCustomParams() throws Exception
    {
        String json = "{\"kty\":\"EC\"," +
                "\"x\":\"14PCFt8uuLb6mbfn1XTOHzcSfZk0nU_AGe2hq91Gvl4\"," +
                "\"y\":\"U0rLlwB8be5YM2ajGyactlplFol7FKJrN83mNAOpuss\"," +
                "\"crv\":\"P-256\"," +
                "\"meh\":\"just some value\"," +
                "\"number\":860}";

        JsonWebKey jwk = JsonWebKey.Factory.newJwk(json);

        String meh = jwk.getOtherParameterValue("meh", String.class);
        assertThat(meh, equalTo("just some value"));
        Number number = jwk.getOtherParameterValue("number", Number.class);
        assertThat(number.intValue(), equalTo(860));

        json = jwk.toJson(PUBLIC_ONLY);
        assertTrue(json.contains("\"meh\""));
        assertTrue(json.contains("\"just some value\""));
        assertTrue(json.contains("\"number\""));
        assertTrue(json.contains("860"));
    }

    @Test
    public void fromKeyWithCustomParams() throws Exception
    {
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(ExampleRsaKeyFromJws.PUBLIC_KEY);
        final String name = "artisanal";
        final String value = "parameter";
        jsonWebKey.setOtherParameter(name, value);
        assertThat(jsonWebKey.getOtherParameterValue(name, String.class), equalTo(value));

        String json = jsonWebKey.toJson(PUBLIC_ONLY);
        assertTrue(json.contains("\""+name+"\""));
        assertTrue(json.contains("\"" + value + "\""));

        jsonWebKey = JsonWebKey.Factory.newJwk(json);
        assertThat(value, equalTo(jsonWebKey.getOtherParameterValue(name, String.class)));
        assertThat(ExampleRsaKeyFromJws.PUBLIC_KEY, equalTo(jsonWebKey.getKey()));
    }

    @Test
    public void roundTripOctKey() throws Exception
    {
        final String name = "artisanal";
        final String value = "parameter";
        String json = "{\"kty\":\"oct\",\"k\":\"jr-TRYPvKkOxw_cBB5y4plEX5cEUT1AawUU7G3id7u4\",\""+name+"\":\""+value+"\"}";
        JsonWebKey jsonWebKey = JsonWebKey.Factory.newJwk(json);
        final Key key = jsonWebKey.getKey();
        assertThat(value, equalTo(jsonWebKey.getOtherParameterValue(name, String.class)));
        final String publicOnlyJson = jsonWebKey.toJson(PUBLIC_ONLY);
        assertFalse(publicOnlyJson.contains("\"k\""));
        assertTrue(publicOnlyJson.contains("\"" + name + "\""));
        assertTrue(publicOnlyJson.contains("\"" + value + "\""));
        final String includeSymmetricJson = jsonWebKey.toJson(INCLUDE_SYMMETRIC);
        assertTrue(includeSymmetricJson.contains("\"k\""));
        assertTrue(includeSymmetricJson.contains("\"" + name + "\""));
        assertTrue(includeSymmetricJson.contains("\"" + value + "\""));
        jsonWebKey = JsonWebKey.Factory.newJwk(includeSymmetricJson);
        assertThat(value, equalTo(jsonWebKey.getOtherParameterValue(name, String.class)));
        assertThat(key, equalTo(jsonWebKey.getKey()));
    }


}
