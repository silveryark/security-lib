package com.silveryark.security;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

@RunWith(SpringRunner.class)
public class SecurityServiceTest {

    JwtSecurityService service;

    private String testPriKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBlBeIiSqiul/oYpEi" +
            "cJIneJ+0jgXXJwHwcWFIFZvFCCogmEklXvMGgh+TMDrHwsvXiclsXxtqK/z9CLep" +
            "sAj0tfehgYkDgYYABACftjREJt98F8pooNj0TKDXP/sg9OevrMo6Lb9jnVAXbJge" +
            "VnlgxZVXE4ULhTjR0qGNWrQ/v9Dc8HB35JRy6Ia+IAHyq8OXInbaitdBAOmQvohL" +
            "4lP5DotgqbxziTLy0Rby+Ybv88ZhhTC1z/DvGfNME4Ji6FllIUYNpTC3OEweSGvD" +
            "cw==";

    private String testPubKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAn7Y0RCbffBfKaKDY9Eyg1z/7IPTn" +
            "r6zKOi2/Y51QF2yYHlZ5YMWVVxOFC4U40dKhjVq0P7/Q3PBwd+SUcuiGviAB8qvD" +
            "lyJ22orXQQDpkL6IS+JT+Q6LYKm8c4ky8tEW8vmG7/PGYYUwtc/w7xnzTBOCYuhZ" +
            "ZSFGDaUwtzhMHkhrw3M=";

    @Before
    public void init() throws InvalidKeySpecException, NoSuchAlgorithmException {
        service = new JwtSecurityService();
        ReflectionTestUtils.setField(service, "pubkey", testPubKey);
        ReflectionTestUtils.setField(service, "prikey", testPriKey);
        service.init();
    }

    @Test
    public void testService() {
        String username = RandomStringUtils.randomAlphanumeric(16);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        int count = RandomUtils.nextInt(10, 16);
        for (int i = 0; i < count; i++) {
            authorities.add(new SimpleGrantedAuthority(RandomStringUtils.randomAlphanumeric(16)));
        }
        Date now = new Date();
        Date tomorrow = DateUtils.addDays(now, 1);
        String jwt = service.encode(username, authorities, now, tomorrow);
        DecodedJWT decode = service.decode(jwt);
        Assert.assertEquals("username should be the same", username, decode.getSubject());
        Assert.assertEquals("authorities should be the same", authorities,
                decode.getClaim(JwtSecurityService.AUTHORITIES).asList(SimpleGrantedAuthority.class));
    }

    @Test
    public void testExpiredToken() {
        String username = RandomStringUtils.randomAlphanumeric(16);
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        int count = RandomUtils.nextInt(10, 16);
        for (int i = 0; i < count; i++) {
            authorities.add(new SimpleGrantedAuthority(RandomStringUtils.randomAlphanumeric(16)));
        }
        Date now = new Date();
        Date yesterday = DateUtils.addDays(now, -1);
        Date tomorrow = DateUtils.addDays(now, 1);
        String jwt = service.encode(username, authorities, yesterday, yesterday);
        try {
            DecodedJWT decode = service.decode(jwt);
            Assert.fail("should throw verify exception");
        } catch (TokenExpiredException e) {

        }

    }
}
