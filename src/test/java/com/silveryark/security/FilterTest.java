package com.silveryark.security;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

@RunWith(SpringRunner.class)
public class FilterTest {
    @Mock
    ReactiveAuthenticationManager manager;

    @Mock
    JwtAuthenticationConverter converter;

    @Test
    public void testFilter() {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(manager, converter);
        Object authenticationManager = ReflectionTestUtils.getField(filter, "authenticationManager");
        Object authenticationConverter = ReflectionTestUtils.getField(filter, "authenticationConverter");
        Assert.assertEquals("should be equal", manager, authenticationManager);
        Assert.assertEquals("should be equal", converter, authenticationConverter);
    }
}
