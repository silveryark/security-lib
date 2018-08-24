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

    protected static final String AUTHORITIES = "authorities";
    //唯一算法
    private static Algorithm algorithm;
    //验证的时候需要的公钥
    @Value("${jwt.pubkey}")
    private String pubkey = null;
    //生成的时候需要私钥，如果在资源服务器里的话就不需要私钥了
    @Value("${jwt.prikey:#{null}}")
    private String prikey = null;

    @PostConstruct
    void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
        //处理公钥
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubkey));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(publicKeySpec);
        ECPrivateKey privateKey = null;
        //处理私钥
        if (prikey != null) {
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(prikey));
            privateKey = (ECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
        }
        //生成算法
        algorithm = Algorithm.ECDSA512(publicKey, privateKey);
    }

    //JWT具体操作类
    DecodedJWT decode(String jwtToken) {
        return JWT
                .require(algorithm)
                .build()
                .verify(jwtToken);
    }

    public String encode(String username, Collection<GrantedAuthority> authorities, Date issuedAt, Date expiredAt) {
        return JWT.create()
                //subject里放用户名
                .withSubject(username)
                //claim里放权限
                .withArrayClaim(AUTHORITIES,
                        authorities.stream().map(GrantedAuthority::getAuthority)
                                .toArray(String[]::new))
                //有效期和超时
                .withIssuedAt(issuedAt)
                .withExpiresAt(expiredAt)
                .sign(algorithm);
    }
}
