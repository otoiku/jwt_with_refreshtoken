package com.github.otoiku.jwt_with_refreshtoken.dto;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class UserAuthentification implements Serializable {
    private String userId;
    private String password;
}
