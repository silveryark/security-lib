package com.silveryark.security;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.function.Function;

@Component
public class JwtAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

    private final JwtSecurityService securityService;

    @Autowired
    public JwtAuthenticationConverter(JwtSecurityService securityService) {
        this.securityService = securityService;
    }

    @Override
    public Mono<Authentication> apply(ServerWebExchange serverWebExchange) {
        return Mono.just(serverWebExchange)
                .map(ServerWebExchange::getRequest)
                .map(ServerHttpRequest::getHeaders)
                .flatMap((HttpHeaders headers) -> {
                    if (headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                        List<String> authorizations = headers.get(HttpHeaders.AUTHORIZATION);
                        DecodedJWT decode = securityService.decode(authorizations.get(0).split(" ")[1]);
                        Claim claim = decode.getClaim(JwtSecurityService.AUTHORITIES);
                        List<SimpleGrantedAuthority> authorities = claim.asList(SimpleGrantedAuthority.class);
                        return Mono.just(new JwtAuthenticationToken(decode, authorities));
                    } else {
                        return Mono.empty();
                    }
                });
    }
}
