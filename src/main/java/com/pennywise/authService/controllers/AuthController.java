package com.pennywise.authService.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.pennywise.authService.dtos.*;
import com.pennywise.authService.services.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    @Autowired
    private AuthService authService;

    @PostMapping("/signup")
    private ResponseEntity<?> signupControl(@RequestBody SignupRequest req, HttpServletRequest request) throws JOSEException {
        log.info("Inside the controller");
        String ip = getIP(request);
        log.info("got ip: {}", ip);
        String userAgent = request.getHeader("User-Agent");
        log.info("got user agent: {}", userAgent);
        String signUpResponse = authService.signUpProcessing(req);
        if(signUpResponse.equals("Failure")){
            return (ResponseEntity<?>) ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR);
        }else{
            return (ResponseEntity<?>) ResponseEntity.status(HttpStatus.OK);
        }
    }

    @PostMapping("/verify")
    private ResponseEntity<?> verifyUser(@RequestBody VerificationRequest req, HttpServletRequest request, HttpServletResponse response) throws JOSEException, JsonProcessingException {
        log.info("Inside the controller");
        String ip = getIP(request);
        log.info("got ip: {}", ip);
        String userAgent = request.getHeader("User-Agent");
        log.info("got user agent: {}", userAgent);
        String deviceId = request.getHeader("X-Device-Id");
        VerificationResponse verificationResponse = authService.otpVerification(req, ip, userAgent, deviceId);

        if (verificationResponse.getMessage().equals("Success")){
            response.addCookie(verificationResponse.getRefreshToken());
            response.addCookie(verificationResponse.getJwe());
            return (ResponseEntity<?>) ResponseEntity.status(HttpStatus.OK);
        }else{
            return (ResponseEntity<?>) ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/login")
    private ResponseEntity<?> freshLoginUser(@RequestBody LoginRequest req, HttpServletRequest request) throws ParseException, JOSEException, JsonProcessingException {
        log.info("Inside the controller");
        String ip = getIP(request);
        log.info("got ip: {}", ip);
        String userAgent = request.getHeader("User-Agent");
        log.info("got user agent: {}", userAgent);
        String deviceId = request.getHeader("X-Device-Id");

        LoginResponse response = authService.freshLogin(req, request, ip, userAgent, deviceId, req.getFreshLogin());

        if(response.getMessage().equals("Successful Login")) return ResponseEntity.status(HttpStatus.OK).body(response);
        else return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    @GetMapping("/login")
    private ResponseEntity<?> loginUser(@RequestBody LoginRequest req, HttpServletRequest request) throws ParseException, JOSEException, JsonProcessingException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info(String.valueOf(auth.isAuthenticated()));

        if(auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)){
            String email = auth.getPrincipal().toString();

            Map<String, Object> response = Map.of(
                    "message", "Successful Login",
                    "email", email
            );
            return ResponseEntity.status(HttpStatus.OK).body(response);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login Needed");
    }

    private String getIP(HttpServletRequest request){
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader != null && !xfHeader.isEmpty()) {
            return xfHeader.split(",")[0];
        }
        return request.getRemoteAddr();
    }

}
