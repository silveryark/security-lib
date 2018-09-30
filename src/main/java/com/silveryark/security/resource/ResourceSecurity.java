package com.silveryark.security.resource;


import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.AuthorityReactiveAuthorizationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceSecurity {

    //所有的filter以及filter的配置都在security-lib里，所以之后的资源服务器只需要加这一个配置就可以了
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         AuthenticationWebFilter authenticationWebFilter,
                                                         AuthorizationWebFilter authorizationWebFilter) {
        return http.exceptionHandling()
                .and()
                .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .authorizeExchange()
                .anyExchange().authenticated()
                .and()
                .httpBasic().disable()
                .formLogin().disable()
                .logout().disable()
                .csrf().disable()
                .build();
    }

    @Bean
    public AuthorizationWebFilter authorizationWebFilter() {
        return new AuthorizationWebFilter(AuthorityReactiveAuthorizationManager.hasRole("USER"));
    }

}
