package com.pennywise.authService.dtos;

import jakarta.servlet.http.Cookie;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponse {
    private Cookie jwe;
    private Cookie refreshToken;
    private String message;
    private String email;
}
