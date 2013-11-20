package org.jose4j.jwa;

import junit.framework.TestCase;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.lang.InvalidAlgorithmException;
import org.junit.Test;

import static org.jose4j.jwa.AlgorithmConstraints.ConstraintType.*;

/**
 */
public class AlgorithmConstraintsTest
{
    @Test
    public void blacklist1() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLACKLIST, "bad", "badder");
        constraints.checkConstraint("good");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void blacklist2() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLACKLIST, "bad", "badder");
        constraints.checkConstraint("bad");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void blacklist3() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLACKLIST, "bad", "badder");
        constraints.checkConstraint("badder");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void blacklistNone() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(BLACKLIST, AlgorithmIdentifiers.NONE);
        constraints.checkConstraint(AlgorithmIdentifiers.NONE);
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void whitelist1() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(WHITELIST, "good", "gooder", "goodest");
        constraints.checkConstraint("bad");
    }

    @Test(expected = InvalidAlgorithmException.class)
    public void whitelist2() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(WHITELIST, "good", "gooder", "goodest");
        constraints.checkConstraint("also bad");
    }

    @Test
    public void whitelist3() throws InvalidAlgorithmException
    {
        AlgorithmConstraints constraints = new AlgorithmConstraints(WHITELIST, "good", "gooder", "goodest");
        constraints.checkConstraint("good");
        constraints.checkConstraint("gooder");
        constraints.checkConstraint("goodest");
    }
}
