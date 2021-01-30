package com.github.otoiku.jwt_with_refreshtoken.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.Instant;

@Table(name = "user")
@Entity
@Getter
@Setter
public class User {
    @Id
    @Column(name = "userid", length = 32, nullable = false)
    private String userId;

    @Column(name = "password", length = 64, nullable = false)
    private String password;

    @Column(name = "refreshtoken", length = 64)
    private String refreshToken;

    @Column(name = "refreshtoken_iat")
    private Instant refreshTokenIssuedAt;
}
