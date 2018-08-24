package com.silveryark.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.RandomStringUtils;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Arrays;

@RunWith(SpringRunner.class)
public class TokenTest {

    @Mock
    DecodedJWT decodedJWT;

    @Before
    public void init() {

    }

    @After
    public void after() {
        Mockito.reset(decodedJWT);
    }

    @Test
    public void testTokenValidation() {
        String username = RandomStringUtils.randomAlphanumeric(16);
        Mockito.when(decodedJWT.getSubject()).thenReturn(username);
        JwtAuthenticationToken token = new JwtAuthenticationToken(decodedJWT,
                Arrays.asList(new SimpleGrantedAuthority("USER"),
                        new SimpleGrantedAuthority("ADMIN")));
        Assert.assertNull("it should not contain any credentials", token.getCredentials());
        Assert.assertEquals("should be the same", username, token.getPrincipal());
        Assert.assertEquals("should be the same", token.getPrincipal(), token.getName());
        Assert.assertTrue("should contain role USER",
                token.getAuthorities().contains(new SimpleGrantedAuthority("USER")));
        Assert.assertTrue("should be authenticated", token.isAuthenticated());
    }

    @Test
    public void testEqual() {
        String username = RandomStringUtils.randomAlphanumeric(16);
        Mockito.when(decodedJWT.getSubject()).thenReturn(username);
        JwtAuthenticationToken token = new JwtAuthenticationToken(decodedJWT,
                Arrays.asList(new SimpleGrantedAuthority("USER"),
                        new SimpleGrantedAuthority("ADMIN")));
        JwtAuthenticationToken token1 = new JwtAuthenticationToken(decodedJWT,
                Arrays.asList(new SimpleGrantedAuthority("USER")));
        Assert.assertNotEquals("should not be the same", token, null);
        Assert.assertNotEquals("should not be the same for authorities", token, token1);
        Assert.assertNotEquals("should not be the same for authorities", token.hashCode(), token1.hashCode());
        JwtAuthenticationToken token2 = new JwtAuthenticationToken(decodedJWT,
                Arrays.asList(new SimpleGrantedAuthority("USER"),
                        new SimpleGrantedAuthority("ADMIN")));
        Assert.assertEquals("should be the same", token, token2);
        Assert.assertEquals("should be the same", token, token);
        Assert.assertEquals("should be the same", token.hashCode(), token2.hashCode());
    }
}
