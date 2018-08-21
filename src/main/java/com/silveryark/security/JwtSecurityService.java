package com.silveryark.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Service
public class JwtSecurityService {

    public static final String AUTHORITIES = "authorities";

    @Value("${jwt.pubkey}")
    private String pubkey;

    @Value("${jwt.prikey:#{null}}")
    private String prikey;

    private Algorithm algorithm;

    @PostConstruct
    void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubkey));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
        ECPrivateKey privateKey = null;
        if (prikey != null) {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(prikey));
            privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        }
        algorithm = Algorithm.ECDSA512(publicKey, privateKey);
    }

    public DecodedJWT decode(String jwtToken) {
        return JWT
                .require(algorithm)
                .build()
                .verify(jwtToken);
    }

    public String encode(String username, Collection<GrantedAuthority> authorities, Date issuedAt, Date expiredAt) {
        return JWT.create()
                .withSubject(username)
                .withArrayClaim(AUTHORITIES,
                        authorities.stream().map((GrantedAuthority authority) -> authority.getAuthority())
                                .toArray(String[]::new))
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiredAt)
                .sign(algorithm);
    }
}
