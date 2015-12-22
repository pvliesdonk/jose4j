package org.jose4j.jws;

import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 *
 */
public class MaintainEncodedPayloadTest
{
    @Test
    public void testOddEncodedPayload() throws Exception
    {
        // There's an extra 'X' at the end of the encoded payload but it still decodes to the same value as when the 'X' isn't there
        // but the signature is over the X and we want to check what was signed rather than what we think should be signed by re-encoding the payload
        final String funkyToken = "eyJhbGciOiJSUzI1NiJ9." +
                "IVRoaXMgaXMgbm8gbG9uZ2VyIGEgdmFjYXRpb24uX." +
                "f6qDgGZ8tCVZ_DhlFwWAZvV-Vv5yQOFSAXVv98vOpgkI6YQd6hjCWaeyaWbMWhV__uiWiEY0SutaQw1y71bXvRPfy12YKpyIlRwvos9L5myA--GGc6o88hDjxxc2PLhhhNazR" +
                "1aSVXIb6wF4PJENb10XDMIuMj9wtzDVnLajS5O3Ptygwx39bRa9XoXrAxbSyEBJSV9nVCQS-wPRaEudDcLRQhKVhMHYJ-3UZn0VVpCz_8KWvw4JOB9jWntS85CPF4RcUaepQJ" +
                "2pz-8gfCrv2qKHKU36FbmqOwKoQZL1dLXH1wp33k7ESt5zivLVPli3tPDVfBa5BmWAMO1mydqGgw";

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(funkyToken);
        jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
        assertThat(jws.getPayload(), equalTo("!This is no longer a vacation."));
    }
}
