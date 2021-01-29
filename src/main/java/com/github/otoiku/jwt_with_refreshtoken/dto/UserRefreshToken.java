package com.github.otoiku.jwt_with_refreshtoken.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserRefreshToken {
    private String refreshToken;
}
