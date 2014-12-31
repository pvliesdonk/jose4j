package org.jose4j.jwt.consumer;

import org.jose4j.jwt.JwtClaimsSet;
import org.jose4j.jwx.JsonWebStructure;

import java.util.List;

/**
*
*/
public class JwtContext
{
    private JwtClaimsSet jwtClaimsSet;
    private List<JsonWebStructure> joseObjects;

    public JwtContext(JwtClaimsSet jwtClaimsSet, List<JsonWebStructure> joseObjects)
    {
        this.jwtClaimsSet = jwtClaimsSet;
        this.joseObjects = joseObjects;
    }

    public JwtClaimsSet getJwtClaimsSet()
    {
        return jwtClaimsSet;
    }

    public List<JsonWebStructure> getJoseObjects()
    {
        return joseObjects;
    }
}
