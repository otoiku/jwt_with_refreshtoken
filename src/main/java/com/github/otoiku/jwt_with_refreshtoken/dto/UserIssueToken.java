package com.github.otoiku.jwt_with_refreshtoken.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
@Getter
@Setter
public class UserIssueToken {
    private String accessToken;
    private String refreshToken;
}
