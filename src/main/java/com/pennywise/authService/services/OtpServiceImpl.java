package com.pennywise.authService.services;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
public class OtpServiceImpl implements OtpService{
    private static final String DIGITS = "0123456789";
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generateOTP(int length) {
        StringBuilder otp = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            otp.append(DIGITS.charAt(secureRandom.nextInt(DIGITS.length())));
        }
        return otp.toString();
    }
}
