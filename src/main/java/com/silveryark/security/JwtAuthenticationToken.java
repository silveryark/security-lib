package com.silveryark.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1;

    private String principal;

    JwtAuthenticationToken(DecodedJWT jwt, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = jwt.getSubject();
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || o.getClass() != this.getClass()) {
            return false;
        }
        JwtAuthenticationToken that = (JwtAuthenticationToken) o;

        return new EqualsBuilder()
                .appendSuper(super.equals(o))
                .append(principal, that.principal)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .appendSuper(super.hashCode())
                .append(principal)
                .toHashCode();
    }
}
