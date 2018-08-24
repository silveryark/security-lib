package com.silveryark.security;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;


@RunWith(SpringRunner.class)
public class ConverterTest {

    @Mock
    ServerWebExchange exchange;

    @Mock
    JwtSecurityService securityService;

    @Mock
    ServerHttpRequest request;

    @Mock
    HttpHeaders headers;

    @Before
    public void init() {
        DecodedJWT mockedJWToken = Mockito.mock(DecodedJWT.class);
        Mockito.when(mockedJWToken.getClaim(JwtSecurityService.AUTHORITIES)).thenReturn(new NullClaim());
        Mockito.when(securityService.decode(Mockito.any())).thenReturn(mockedJWToken);
    }

    @After
    public void after() {
        Mockito.reset(exchange, securityService, request, headers);
    }

    @Test
    public void testConverter() {
        Mockito.when(exchange.getRequest()).thenReturn(request);
        Mockito.when(request.getHeaders()).thenReturn(headers);
        Mockito.when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(true);
        Mockito.when(headers.get(HttpHeaders.AUTHORIZATION)).thenReturn(Collections.singletonList("Bearer [TOKEN]"));
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter(securityService);
        Mono<Authentication> apply = converter.apply(exchange);
        apply.map((Authentication auth) -> {
            Assert.assertTrue("It should exchange convert to JwtAuthenticationToken",
                    auth instanceof JwtAuthenticationToken);
            return auth;
        }).block();
    }

    @Test
    public void testNoAuth() {
        Mockito.when(exchange.getRequest()).thenReturn(request);
        Mockito.when(request.getHeaders()).thenReturn(headers);
        Mockito.when(headers.containsKey(HttpHeaders.AUTHORIZATION)).thenReturn(false);
        Mockito.when(headers.get(HttpHeaders.AUTHORIZATION)).thenReturn(Collections.emptyList());
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter(securityService);
        Mono<Authentication> apply = converter.apply(exchange);
        Authentication authentication = apply.block();
        Assert.assertNull("should be null for no authorization.", authentication);
    }
}
