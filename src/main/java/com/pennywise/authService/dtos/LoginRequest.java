package com.pennywise.authService.dtos;

public class LoginRequest {

    private String email;
    private String pass;
    private Boolean freshLogin;

    public Boolean getFreshLogin() {
        return freshLogin;
    }

    public void setFreshLogin(Boolean freshLogin) {
        this.freshLogin = freshLogin;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPass() {
        return pass;
    }

    public void setPass(String pass) {
        this.pass = pass;
    }
}
