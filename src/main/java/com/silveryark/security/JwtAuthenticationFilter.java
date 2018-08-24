package com.silveryark.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationFilter extends AuthenticationWebFilter {

    @Autowired
    public JwtAuthenticationFilter(ReactiveAuthenticationManager authenticationManager,
                                   JwtAuthenticationConverter converter) {
        super(authenticationManager);
        //从exchange里抽取authentication数据
        super.setAuthenticationConverter(converter);
    }
}
