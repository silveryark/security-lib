package com.silveryark.security;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.junit4.SpringRunner;
import reactor.core.publisher.Mono;

@RunWith(SpringRunner.class)
public class ManagerTest {

    @Mock
    Authentication authentication;

    @Test
    public void testNoChange() {
        JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager();
        Mono<Authentication> authenticate = manager.authenticate(authentication);
        authenticate.map(authentication1 -> {
            Assert.assertEquals("should be equal", authentication1, authentication);
            return true;
        }).block();
    }
}
