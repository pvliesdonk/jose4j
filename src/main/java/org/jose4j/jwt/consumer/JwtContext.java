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

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwx.JsonWebStructure;

import java.util.List;

/**
*
*/
public class JwtContext
{
    private String jwt;
    private JwtClaims jwtClaims;
    private List<JsonWebStructure> joseObjects;

    public JwtContext(JwtClaims jwtClaims, List<JsonWebStructure> joseObjects)
    {
        this.jwtClaims = jwtClaims;
        this.joseObjects = joseObjects;
    }

    public JwtContext(String jwt, JwtClaims jwtClaims, List<JsonWebStructure> joseObjects)
    {
        this.jwt = jwt;
        this.jwtClaims = jwtClaims;
        this.joseObjects = joseObjects;
    }

    public JwtClaims getJwtClaims()
    {
        return jwtClaims;
    }

    /**
     * All of the JOSE objects that comprise the JWT. When the JWT is nested,
     * the first item in the list is the inner most JOSE object.
     * @return the list of JOSE objects that comprise the JWT
     */
    public List<JsonWebStructure> getJoseObjects()
    {
        return joseObjects;
    }

    public String getJwt()
    {
        return jwt;
    }
}
