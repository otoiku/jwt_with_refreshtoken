package com.github.otoiku.jwt_with_refreshtoken.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.github.otoiku.jwt_with_refreshtoken.dto.UserIssueToken;
import com.github.otoiku.jwt_with_refreshtoken.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class Controller {
    @Value("${jwt.accesstoken.secretkey}")
    private String accessTokenSecret;

    private JwtUserDetailsService userDetailsService;

    public Controller(JwtUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/refreshToken")
    public UserIssueToken refreshToken(@RequestBody UserIssueToken token) {
        final DecodedJWT jwt = JWT.decode(token.getAccessToken());

        try {
            JWT.require(Algorithm.HMAC512(accessTokenSecret.getBytes())).build().verify(jwt);
        } catch (TokenExpiredException e) {
            // allow expired access token for user authentication
        } catch (Exception e) {
            throw e;
        }

        if (userDetailsService.verifyRefreshToken(jwt.getSubject(), token.getRefreshToken())) {
            return userDetailsService.issueToken(jwt.getSubject());
        } else {
            throw new BadCredentialsException("Invalid refresh token!");
        }
    }
}
