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

package org.jose4j.jwt;

import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.Assert;
import org.junit.Test;

import java.util.*;

import static org.hamcrest.CoreMatchers.*;
import static org.jose4j.jwt.ReservedClaimNames.*;

/**
 *
 */
public class JwtClaimsTest
{

    public static final int DEFAULT_JTI_LENGTH = 22;  // base64url of 128bits is 22 chars

    @Test (expected = MalformedClaimException.class)
    public void testGetBadIssuer() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"iss\":{\"name\":\"value\"}}");
        claims.getIssuer();
    }

    @Test
    public void testGetNullIssuer() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"exp\":123456781}");
        Assert.assertNull(claims.getIssuer());
    }

    @Test
    public void testGetIssuer() throws InvalidJwtException, MalformedClaimException
    {
        String issuer = "https//idp.example.com";
        JwtClaims claims = JwtClaims.parse("{\"iss\":\"" + issuer + "\"}");
        Assert.assertThat(issuer, equalTo(claims.getIssuer()));
    }

    @Test
    public void testGetNullAudience() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"iss\":\"some-issuer\"}");
        Assert.assertNull(claims.getAudience());
    }

    @Test
    public void testGetAudienceSingleInArray() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"aud\":[\"one\"]}");
        List<String> audiences = claims.getAudience();
        Assert.assertThat(1, equalTo(audiences.size()));
        Assert.assertThat("one", equalTo(audiences.get(0)));
    }

    @Test
    public void testGetAudienceSingleValue() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"aud\":\"one\"}");
        List<String> audiences = claims.getAudience();
        Assert.assertThat(1, equalTo(audiences.size()));
        Assert.assertThat("one", equalTo(audiences.get(0)));
    }

    @Test
    public void testGetAudienceMultipleInArray() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"aud\":[\"one\",\"two\",\"three\"]}");
        List<String> audiences = claims.getAudience();
        Assert.assertThat(3, equalTo(audiences.size()));
        Iterator<String> iterator = audiences.iterator();
        Assert.assertThat("one", equalTo(iterator.next()));
        Assert.assertThat("two", equalTo(iterator.next()));
        Assert.assertThat("three", equalTo(iterator.next()));
    }

    @Test
    public void testGetAudienceArray() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"aud\":[]}");
        List<String> audiences = claims.getAudience();
        Assert.assertThat(0, equalTo(audiences.size()));
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadAudience1() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"aud\":1996}");
        claims.getAudience();
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadAudience2() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"aud\":[\"value\", \"other\", 2, \"value\"]}");
        claims.getAudience();
    }

    @Test
    public void testGetNullSubject() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"exp\":123456781}");
        Assert.assertNull(claims.getSubject());
    }

    @Test
    public void testGetSubject() throws InvalidJwtException, MalformedClaimException
    {
        String sub = "subject@example.com";
        JwtClaims claims = JwtClaims.parse("{\"sub\":\"" + sub + "\"}");
        Assert.assertThat(sub, equalTo(claims.getSubject()));
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadSubject() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"sub\":[\"nope\", \"not\", \"good\"]}");
        claims.getSubject();
    }

    @Test
    public void testGetNullJti() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"whatever\":123456781}");
        Assert.assertNull(claims.getJwtId());
    }

    @Test
    public void testGetJti() throws InvalidJwtException, MalformedClaimException
    {
        String jti = "Xk9c2inNN8fFs60epZil3";
        JwtClaims claims = JwtClaims.parse("{\"jti\":\"" + jti + "\"}");
        Assert.assertThat(jti, equalTo(claims.getJwtId()));
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadJti() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"jti\":[\"nope\", \"not\", \"good\"]}");
        claims.getJwtId();
    }

    @Test
    public void generateAndGetJwt() throws MalformedClaimException
    {
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        String jwtId = claims.getJwtId();
        Assert.assertThat(DEFAULT_JTI_LENGTH, equalTo(jwtId.length()));

        claims.setJwtId("igotyourjtirighthere");
        jwtId = claims.getJwtId();
        Assert.assertThat(jwtId, equalTo("igotyourjtirighthere"));
    }

    @Test
    public void testGetNullExp() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"right\":123456781}");
        Assert.assertNull(claims.getExpirationTime());
    }

    @Test
    public void testGetExp() throws InvalidJwtException, MalformedClaimException
    {
        long exp = 1418823169;
        JwtClaims claims = JwtClaims.parse("{\"exp\":" + exp + "}");
        Assert.assertThat(exp, equalTo(claims.getExpirationTime().getValue()));
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadExp() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"exp\":\"nope\"}");
        claims.getExpirationTime();
    }

    @Test
    public void testGetNullNbf() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"right\":123456781}");
        Assert.assertNull(claims.getNotBefore());
    }

    @Test
    public void testGetNbf() throws InvalidJwtException, MalformedClaimException
    {
        long nbf = 1418823109;
        JwtClaims claims = JwtClaims.parse("{\"nbf\":" + nbf + "}");
        Assert.assertThat(nbf, equalTo(claims.getNotBefore().getValue()));
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadNbf() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"nbf\":[\"nope\", \"not\", \"good\"]}");
        claims.getNotBefore();
    }

    @Test
    public void testGetNullIat() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"right\":123456781, \"wrong\":123452781}");
        Assert.assertNull(claims.getIssuedAt());
    }

    @Test
    public void testGetIat() throws InvalidJwtException, MalformedClaimException
    {
        long nbf = 1418823119;
        JwtClaims claims = JwtClaims.parse("{\"iat\":" + nbf + "}");
        Assert.assertThat(nbf, equalTo(claims.getIssuedAt().getValue()));
    }

    @Test (expected = MalformedClaimException.class)
    public void testGetBadIat() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = JwtClaims.parse("{\"iat\":\"not\"}");
        claims.getIssuedAt();
    }

    @Test
    public void testBasicCreate() throws GeneralJwtException
    {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("subject");
        claims.setAudience("audience");
        claims.setIssuer("issuer");
        claims.setJwtId("id");
        claims.setExpirationTime(NumericDate.fromSeconds(231458800));
        claims.setIssuedAt(NumericDate.fromSeconds(231459000));
        claims.setNotBefore(NumericDate.fromSeconds(231459600));
        String jsonClaims = claims.toJson();

        Assert.assertThat(jsonClaims, containsString("\"iss\":\"issuer\""));
        Assert.assertThat(jsonClaims, containsString("\"aud\":\"audience\""));
        Assert.assertThat(jsonClaims, containsString("\"sub\":\"subject\""));
        Assert.assertThat(jsonClaims, containsString("\"jti\":\"id\""));
        Assert.assertThat(jsonClaims, containsString("\"exp\":231458800"));
        Assert.assertThat(jsonClaims, containsString("\"iat\":231459000"));
        Assert.assertThat(jsonClaims, containsString("\"nbf\":231459600"));
    }

    @Test
    public void testSettingAud() throws GeneralJwtException
    {
        JwtClaims claims = new JwtClaims();

        claims.setAudience("audience");
        Assert.assertThat(claims.toJson(), containsString("\"aud\":\"audience\""));

        claims.setAudience("audience1", "audience2", "outlier");
        Assert.assertThat(claims.toJson(), containsString("\"aud\":[\"audience1\",\"audience2\",\"outlier\"]"));

        claims.setAudience(Collections.<String>singletonList("audience"));
        Assert.assertThat(claims.toJson(), containsString("\"aud\":\"audience\""));

        List<String> list = new ArrayList<>();
        list.add("one");
        list.add("two");
        list.add("three");
        claims.setAudience(list);
        Assert.assertThat(claims.toJson(), containsString("\"aud\":[\"one\",\"two\",\"three\"]"));

        Assert.assertFalse(claims.getClaimsMap().isEmpty());

        claims.unsetClaim(AUDIENCE);
        Assert.assertThat(claims.toJson(), equalTo("{}"));

        Assert.assertTrue(claims.getClaimsMap().isEmpty());
    }

    @Test
    public void testCreateWithHelpers() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims claims = new JwtClaims();
        claims.setSubject("subject");
        claims.setAudience("audience");
        claims.setIssuer("issuer");
        claims.setGeneratedJwtId();
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(5);
        String jsonClaims = claims.toJson();

        Assert.assertThat(jsonClaims, containsString("\"iss\":\"issuer\""));
        Assert.assertThat(jsonClaims, containsString("\"aud\":\"audience\""));
        Assert.assertThat(jsonClaims, containsString("\"sub\":\"subject\""));
        Assert.assertThat(jsonClaims, containsString("\"jti\":\""));
        Assert.assertThat(jsonClaims, containsString("\"exp\":"));
        Assert.assertThat(jsonClaims, containsString("\"iat\":"));
        Assert.assertThat(jsonClaims, containsString("\"nbf\":"));

        JwtClaims parsedClaims = JwtClaims.parse(jsonClaims);

        Assert.assertThat(DEFAULT_JTI_LENGTH, equalTo(parsedClaims.getJwtId().length()));

        long nowMillis = System.currentTimeMillis();

        long nbfMillis = parsedClaims.getNotBefore().getValueInMillis();
        Assert.assertTrue(nbfMillis <= (nowMillis - 300000));
        Assert.assertTrue(nbfMillis > (nowMillis - 302000));

        final long iatMIllis = parsedClaims.getIssuedAt().getValueInMillis();
        Assert.assertTrue(iatMIllis < (nowMillis + 100));
        Assert.assertTrue((nowMillis - 2000) < iatMIllis);


        final long expMillis = parsedClaims.getExpirationTime().getValueInMillis();
        Assert.assertTrue(expMillis > (nowMillis + 598000));
        Assert.assertTrue(expMillis < (nowMillis + 600000));
    }

    @Test
    public void testSetExpirationTimeMinutesInTheFuturePartOfMinute() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setExpirationTimeMinutesInTheFuture(0.167f);
        jwtClaims = JwtClaims.parse(jwtClaims.toJson());
        NumericDate expirationTime = jwtClaims.getExpirationTime();
        NumericDate checker = NumericDate.now();
        Assert.assertTrue(checker.isBefore(expirationTime));
        checker.addSeconds(9);
        Assert.assertTrue(checker.isBefore(expirationTime));
        checker.addSeconds(2);
        Assert.assertFalse(checker.isBefore(expirationTime));
    }

    @Test
    public void testGetClaimsMap() throws InvalidJwtException, MalformedClaimException
    {
        String json = "{\"sub\":\"subject\",\"aud\":\"audience\",\"iss\":\"issuer\"," +
                "\"jti\":\"mz3uxaCcLmQ2cwAV3oJxEQ\",\"exp\":1418906607," +
                "\"email\":\"user@somewhere.io\", \"name\":\"Joe User\", \"someclaim\":\"yup\"}";

        JwtClaims jwtClaims = JwtClaims.parse(json);
        Map<String, Object> claimsMap = jwtClaims.getClaimsMap(INITIAL_REGISTERED_CLAIM_NAMES);
        Assert.assertThat(3, equalTo(claimsMap.size()));

        claimsMap = jwtClaims.getClaimsMap();
        Assert.assertThat(8, equalTo(claimsMap.size()));

        Collection<String> claimNames = jwtClaims.getClaimNames(INITIAL_REGISTERED_CLAIM_NAMES);
        Assert.assertThat(3, equalTo(claimNames.size()));

        claimNames = jwtClaims.getClaimNames(Collections.singleton(AUDIENCE));
        Assert.assertThat(7, equalTo(claimNames.size()));

        claimNames = jwtClaims.getClaimNames();
        Assert.assertThat(8, equalTo(claimNames.size()));

        Assert.assertThat(json, is(equalTo(jwtClaims.getRawJson())));
    }

    @Test
    public void testGettingHelpers() throws InvalidJwtException, MalformedClaimException
    {
        String stringClaimName = "string";
        String stringClaimValue = "a value";
        String stringArrayClaimName = "array";
        String json = "{\""+stringClaimName+"\":\""+stringClaimValue+"\", \""+stringArrayClaimName+"\":[\"one\", \"two\", \"three\"]}";
        JwtClaims claims = JwtClaims.parse(json);
        Assert.assertTrue(claims.isClaimValueOfType(stringClaimName, String.class));
        Assert.assertTrue(claims.isClaimValueString(stringClaimName));
        Assert.assertFalse(claims.isClaimValueStringList(stringClaimName));
        Assert.assertFalse(claims.isClaimValueOfType(stringClaimName, Number.class));
        Assert.assertFalse(claims.isClaimValueOfType(stringClaimName, Long.class));
        Assert.assertFalse(claims.isClaimValueOfType(stringClaimName, List.class));
        Assert.assertFalse(claims.isClaimValueOfType(stringClaimName, Boolean.class));

        Assert.assertTrue(claims.isClaimValueStringList(stringArrayClaimName));
        Assert.assertTrue(claims.isClaimValueOfType(stringArrayClaimName, List.class));
        Assert.assertFalse(claims.isClaimValueString(stringArrayClaimName));
        Assert.assertFalse(claims.isClaimValueOfType(stringArrayClaimName, String.class));
        Assert.assertFalse(claims.isClaimValueOfType(stringArrayClaimName, Number.class));
        Assert.assertFalse(claims.isClaimValueOfType(stringArrayClaimName, Long.class));
        Assert.assertTrue(claims.isClaimValueOfType(stringArrayClaimName, List.class));
        Assert.assertFalse(claims.isClaimValueOfType(stringArrayClaimName, Boolean.class));

        String nonexistentClaimName= "nope";
        Assert.assertFalse(claims.isClaimValueOfType(nonexistentClaimName, String.class));
        Assert.assertFalse(claims.isClaimValueOfType(nonexistentClaimName, List.class));
        Assert.assertFalse(claims.isClaimValueOfType(nonexistentClaimName, Boolean.class));
        Assert.assertFalse(claims.isClaimValueOfType(nonexistentClaimName, Number.class));

        Assert.assertFalse(claims.isClaimValueString(nonexistentClaimName));
        Assert.assertFalse(claims.isClaimValueStringList(nonexistentClaimName));

        Assert.assertThat(stringClaimValue, equalTo(claims.getStringClaimValue(stringClaimName)));
        Assert.assertNull(claims.getStringClaimValue(nonexistentClaimName));
        Assert.assertNull(claims.getStringListClaimValue(nonexistentClaimName));
    }

    @Test
    public void testSomeSettingAndGettingHelpers() throws InvalidJwtException, MalformedClaimException
    {
        JwtClaims jcs = new JwtClaims();
        Assert.assertNull(jcs.getRawJson());

        jcs.setStringClaim("s", "value");
        jcs.setStringListClaim("sa1", "a", "b", "c");
        jcs.setStringListClaim("sa2", Arrays.asList("1","2"));
        jcs.setStringListClaim("sa3", "single");
        jcs.setStringListClaim("sa4", Collections.singletonList("single"));
        jcs.setStringListClaim("sa5");
        jcs.setStringListClaim("sa6", Collections.<String>emptyList());
        jcs.setClaim("n", 16);
        jcs.setClaim("n2", 2314596000L);

        List<Object> ml = new ArrayList<>();
        ml.add("string");
        ml.add(47);
        ml.add("meh");
        ml.add(new String[] {"a", "B"});
        jcs.setClaim("mixed-list", ml);

        JwtClaims parsedJcs = JwtClaims.parse(jcs.toJson());
        Assert.assertThat(parsedJcs.getStringClaimValue("s"), equalTo("value"));
        Assert.assertTrue(parsedJcs.hasClaim("s"));
        Assert.assertNotNull(parsedJcs.getClaimValue("s"));
        Assert.assertThat(parsedJcs.getStringListClaimValue("sa1"), equalTo(Arrays.asList("a", "b", "c")));
        Assert.assertThat(parsedJcs.getStringListClaimValue("sa2"), equalTo(Arrays.asList("1", "2")));
        Assert.assertThat(parsedJcs.getStringListClaimValue("sa3"), equalTo(Collections.singletonList("single")));
        Assert.assertThat(parsedJcs.getStringListClaimValue("sa4"), equalTo(Collections.singletonList("single")));
        Assert.assertThat(parsedJcs.getStringListClaimValue("sa5"), equalTo(Collections.<String>emptyList()));
        Assert.assertThat(parsedJcs.getStringListClaimValue("sa6"), equalTo(Collections.<String>emptyList()));
        Assert.assertNull(parsedJcs.getStringListClaimValue("nope"));
        Assert.assertNull(parsedJcs.getStringClaimValue("nope"));
        Assert.assertNull(parsedJcs.getClaimValue("nope", Boolean.class));
        Assert.assertFalse(parsedJcs.hasClaim("nope"));
        Assert.assertNull(parsedJcs.getClaimValue("nope"));
        Assert.assertTrue(parsedJcs.isClaimValueOfType("n", Number.class));
        Number n = jcs.getClaimValue("n", Number.class);
        Assert.assertThat(16, equalTo(n.intValue()));
        Assert.assertThat(16L, equalTo(n.longValue()));

        Assert.assertTrue(parsedJcs.isClaimValueOfType("n2", Number.class));
        Number n2 = jcs.getClaimValue("n2", Number.class);
        Assert.assertThat(2314596000L, equalTo(n2.longValue()));

        Assert.assertFalse(parsedJcs.isClaimValueStringList("mixed-list"));
        Assert.assertTrue(parsedJcs.isClaimValueOfType("mixed-list", List.class));
        Assert.assertThat(4, equalTo(parsedJcs.getClaimValue("mixed-list", List.class).size()));
    }

    @Test
    public void testFlattenClaims() throws InvalidJwtException, MalformedClaimException
    {
        String j =
                "{\n" +
                "\"a\":\"av\",\n" +
                "\"b\":false,\n" +
                "\"c\":{\"cc1\":\"ccv1\",\"cc2\":\"ccv2\",\"cc3\":[\"a\",\"b\",\"c\"],\"cc4\":true},\n" +
                "\"d\":[\"dv1\",\"dv2\",{\"dx\":\"123\"},{\"dxx\":\"abc\"},\"dvlast\"],\n" +
                "\"e\":2.71828,\n" +
                "\"f\":{\"fa\":{\"fb\":{\"fc\":\"value\", \"fc2\":{\"fd\":\"ddd\"}, \"fc3\":\"value3\"}}},\n" +
                "}";
        JwtClaims jcs = JwtClaims.parse(j);
        Map<String, List<Object>> claims = jcs.flattenClaims(Collections.<String>emptySet());

        Assert.assertThat("av", equalTo(claims.get("a").get(0)));
        Assert.assertThat(1, equalTo(claims.get("a").size()));

        Assert.assertThat(false, equalTo(claims.get("b").get(0)));
        Assert.assertThat(1, equalTo(claims.get("b").size()));

        Assert.assertNull(claims.get("c"));
        Assert.assertThat("ccv1", equalTo(claims.get("c.cc1").get(0)));
        Assert.assertThat(1, equalTo(claims.get("c.cc1").size()));
        Assert.assertThat("ccv2", equalTo(claims.get("c.cc2").get(0)));
        Assert.assertThat(1, equalTo(claims.get("c.cc2").size()));
        Assert.assertThat("a", equalTo(claims.get("c.cc3").get(0)));
        Assert.assertThat("b", equalTo(claims.get("c.cc3").get(1)));
        Assert.assertThat("c", equalTo(claims.get("c.cc3").get(2)));
        Assert.assertThat(3, equalTo(claims.get("c.cc3").size()));
        Assert.assertThat(true, equalTo(claims.get("c.cc4").get(0)));
        Assert.assertThat(1, equalTo(claims.get("c.cc4").size()));

        Assert.assertThat("123", equalTo(claims.get("d.dx").get(0)));
        Assert.assertThat("abc", equalTo(claims.get("d.dxx").get(0)));
        Assert.assertThat("dv1", equalTo(claims.get("d").get(0)));
        Assert.assertThat("dv2", equalTo(claims.get("d").get(1)));
        Assert.assertThat("dvlast", equalTo(claims.get("d").get(2)));

        Assert.assertThat(2.71828D, equalTo(claims.get("e").get(0)));

        Assert.assertThat("value", equalTo(claims.get("f.fa.fb.fc").get(0)));
        Assert.assertThat("ddd", equalTo(claims.get("f.fa.fb.fc2.fd").get(0)));
        Assert.assertThat("value3", equalTo(claims.get("f.fa.fb.fc3").get(0)));
    }

    @Test
    public void testFlattenClaimsOpenIdAddress() throws InvalidJwtException, MalformedClaimException
    {
        String j =  // example claims from http://openid.net/specs/openid-connect-core-1_0.html OpenID Connect Core 1.0 incorporating errata set 1
                "  {\n" +
                "   \"address\": {\n" +
                "     \"street_address\": \"1234 Hollywood Blvd.\",\n" +
                "     \"locality\": \"Los Angeles\",\n" +
                "     \"region\": \"CA\",\n" +
                "     \"postal_code\": \"90210\",\n" +
                "     \"country\": \"US\"},\n" +
                "   \"phone_number\": \"+1 (310) 123-4567\"\n" +
                "  }";
        JwtClaims jcs = JwtClaims.parse(j);
        Map<String, List<Object>> claims = jcs.flattenClaims();
        for (String k : claims.keySet())
        {
            Assert.assertThat(1, equalTo(claims.get(k).size()));
        }

        Assert.assertThat("1234 Hollywood Blvd.", equalTo(claims.get("address.street_address").get(0)));
        Assert.assertThat("Los Angeles", equalTo(claims.get("address.locality").get(0)));
        Assert.assertThat("CA", equalTo(claims.get("address.region").get(0)));
        Assert.assertThat("90210", equalTo(claims.get("address.postal_code").get(0)));
        Assert.assertThat("US", equalTo(claims.get("address.country").get(0)));
        Assert.assertThat("+1 (310) 123-4567", equalTo(claims.get("phone_number").get(0)));
    }

    @Test
    public void testSimpleClaimsExampleFromDraft() throws InvalidJwtException, MalformedClaimException
    {
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-3.1
        String json = "     {\"iss\":\"joe\",\n" +
                "      \"exp\":1300819380,\n" +
                "      \"http://example.com/is_root\":true}";

        JwtClaims jcs = JwtClaims.parse(json);
        Assert.assertThat("joe", equalTo(jcs.getIssuer()));
        Assert.assertThat(NumericDate.fromSeconds(1300819380), equalTo(jcs.getExpirationTime()));
        Assert.assertTrue(jcs.getClaimValue("http://example.com/is_root", Boolean.class));
    }

    @Test
    public void testNonIntegerNumericDates() throws InvalidJwtException, MalformedClaimException
    {
        // JWT's NumericDate says that "non-integer values can be represented"
        // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-2
        // I always just assumed that it could only be integers (maybe b/c of the former IntDate name )
        // but looking at the text again it looks like maybe fractional values has always been possible.
        // I'm not sure I see value in truly supporting sub-second accuracy (right now, anyway) but do want to
        // ensure that we handle such values reasonably, if we receive them. This test checks that we don't fail
        // and just truncate the sub-second part.

        JwtClaims jcs = JwtClaims.parse("{\"sub\":\"brian.d.campbell\", \"nbf\":1430602000.173, \"iat\":1430602060.5, \"exp\":1430602600.77}");
        Assert.assertThat(NumericDate.fromSeconds(1430602600), equalTo(jcs.getExpirationTime()));
        Assert.assertThat(NumericDate.fromSeconds(1430602060), equalTo(jcs.getIssuedAt()));
        Assert.assertThat(NumericDate.fromSeconds(1430602000), equalTo(jcs.getNotBefore()));
    }
}
