package com.pennywise.authService.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.pennywise.authService.configs.RedisConfig;
import com.pennywise.authService.db_entities.RefreshTokenEntity;
import com.pennywise.authService.db_entities.UserEntity;
import com.pennywise.authService.dtos.*;
import com.pennywise.authService.repositories.RefreshTokenRepository;
import com.pennywise.authService.repositories.UserRepository;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    public UserRepository userRepository;

    @Autowired
    public RefreshTokenRepository rtrepository;

    Argon2 argon2 = Argon2Factory.create();


    private final Argon2PasswordEncoder encoder;

    @Autowired
    public AuthService(Argon2PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Autowired
    public EmailService emailService;

    @Autowired
    public OtpService otpService;

    @Autowired
    public RedisConfig redisConfig;

    public String  signUpProcessing(SignupRequest request) throws JOSEException {
        log.info("inside service");
        String name = request.name;
        String email = request.email;
        String password = request.password;
        if(validatePass(password)){
            log.info("password validated");
            String passHash = encoder.encode(password);
            log.info("password hashed to : {}", passHash);

            UserEntity newUser = new UserEntity();
            newUser.setEmail(email);
            newUser.setPassword(passHash);
            newUser.setName(name);
            log.info("user created: {} & {}", newUser.name, newUser.email);
            UserEntity user = userRepository.save(newUser);
            log.info("User saved successfully");

            //trigger send mail
            String otp = otpService.generateOTP(8);
            redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set(email, otp, Duration.ofMinutes(5));

            EmailFormat mailBody = new EmailFormat();
            mailBody.setRecipient(email);
            mailBody.setMsgBody(String.format("Please verify using this OTP: %s. It is valid for the next 5 minutes.", otp));
            mailBody.setSubject("Verification OTP");
            emailService.sendSimpleMail(mailBody);
            return "Success";
        }
        else return "Failure";
    }

    public VerificationResponse otpVerification(VerificationRequest req, String ip, String userAgent, String deviceId) throws JOSEException, JsonProcessingException {
        VerificationResponse response = new VerificationResponse();
        response.setJwe(null);
        response.setRefreshToken(null);
        String email = req.email;
        String otp = req.otp;
        if(email==null || otp==null){
            response.setMessage("Invalid Request");
        }

        String otpInCache = redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().get(email).toString();

        if(otp.equals(otpInCache)){
            UserEntity user = userRepository.findByEmail(email);
            markUserVerified(email, true);

            //create jwe token
            String jweToken = createJWE(email, ip, deviceId);
            //send in https secure cookie
            Cookie jweCookie = new Cookie("access_token", jweToken);
            jweCookie.setHttpOnly(true);
            jweCookie.setSecure(false); //TODO: Set true for prod
            jweCookie.setPath("/");
            jweCookie.setMaxAge(15 * 60);

            //create refresh token
            String refreshToken = createRefreshToken();
            RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
            refreshTokenEntity.setToken(refreshToken);
            refreshTokenEntity.setExpiresAt(Instant.now().plus(Duration.of(7, ChronoUnit.DAYS)));
            refreshTokenEntity.setUser(user);
            refreshTokenEntity.setIp_addr(ip);
            refreshTokenEntity.setUserAgent(userAgent);
            log.info("Refresh Token obj formed: {}", refreshTokenEntity);

            //refresh token
            Cookie refreshCookie = new Cookie("refresh_token", refreshToken);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(false); //TODO: Set true for prod
            refreshCookie.setPath("/");
            refreshCookie.setMaxAge(60 * 60 * 24 * 7);

            //save refresh token in the db
            RefreshTokenEntity rtSaved = rtrepository.save(refreshTokenEntity);
            log.info("Refresh Token saved successfully");

            ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());

            String jsonRT = mapper.writeValueAsString(rtSaved);

            String keyForRT = "refresh:"+email+":"+deviceId;
            redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set(keyForRT, jsonRT);

            redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).delete(email);

            response.setJwe(jweCookie);
            response.setRefreshToken(refreshCookie);
            response.setMessage("Success");
        } else {
            response.setMessage("Failure");
        }

        log.info(response.getMessage());

        return response;
    }

    public void userExistingLogin(LoginRequest loginReq, HttpServletRequest httpReq, String ip, String userAgent, String deviceId) throws ParseException, JOSEException, JsonProcessingException {
//        if(!loginReq.getFreshLogin()){
//            //TODO: Get ip and user agent (Refactor this to be inside service and not controller)
//            Cookie[] cookies = httpReq.getCookies();
//            String jweToken = new String();
//            for(Cookie c: cookies){
//                if(c.getName().equals("access_token")){
//                    jweToken = c.getValue();
//                }
//                break;
//            }
//
//            String responseMessage = "";
//
//            String secret = redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().get("jweSecret").toString();
//
//            JWEObject jwe = JWEObject.parse(jweToken);
//            jwe.decrypt(new DirectDecrypter(Base64.getDecoder().decode(secret)));
//            JWTClaimsSet claims = JWTClaimsSet.parse(jwe.getPayload().toJSONObject());
//
//            String eat = claims.getClaimAsString("eat");
//            String userEmail = claims.getClaimAsString("email");
//            Instant jwtExpiryTime = Instant.parse(eat);
//            Instant now = Instant.now();
//            if(!jwtExpiryTime.isAfter(now)){
//                //TODO: refresh token flow refactor
//
//                String rtKey = "refresh:"+userEmail+":"+deviceId; //TODO: this device id will be sent from frontend where it is stored in local storage
//                String rtFromCache = redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().get(rtKey).toString();
//                ObjectMapper mapper  = new ObjectMapper();
//                RefreshTokenEntity obj = mapper.readValue(rtFromCache, RefreshTokenEntity.class);
//
////            Optional<List<RefreshTokenEntity>> opt_token = rtrepository.findByUserEmail(userEmail);
////                //Refactored this to include list of refresh tokens because a user can have multiple sessions on different devices
////            List<RefreshTokenEntity> tokens = opt_token.get();
////            Optional<RefreshTokenEntity> matchedToken = tokens.stream()
////                    .filter(token -> token.getIp_addr().equals(ip))
////                    .filter(token -> token.getUserAgent().equals(userAgent))
////                    .findFirst();
////            RefreshTokenEntity token = matchedToken.get();
//                if (!obj.getExpiresAt().isAfter(now) || obj.getRevoked()) {
//                    //REFRESH TOKEN INVALID - redirect to login
//                    return "Login Needed";
//                } else {
//                    //REFRESH TOKEN VALID (issue new jwt)
//                    String newJwe = createJWE(userEmail, ip, deviceId); //TODO: send in cookie
//                    String newToken = createRefreshToken();
//                    Instant usedTime = Instant.now();
//                    obj.setUsedAt(usedTime);
//                    obj.setToken(newToken);
//                    //update refresh token in redis
//                    redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set(rtKey, mapper.writeValueAsString(obj));
//
//                    //TODO: whenever a jwt token is refreshed, we rotate refresh tokens as bg process using rabbitmq
//                    rtrepository.updateUsedAtAndTokenHashById(usedTime, newToken, obj.getId());
//
//                }
//            }else{
//                UserEntity user = userRepository.findByEmail(userEmail);
//                if(user!=null){
//                    if(user.getVerified())  responseMessage = "Success";
//                    else {
//                        //Verification Flow
//                        //trigger send mail
//                        String otp = otpService.generateOTP(8);
//                        redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set(userEmail, otp, Duration.ofMinutes(5));
//
//                        EmailFormat mailBody = new EmailFormat();
//                        mailBody.setRecipient(userEmail);
//                        mailBody.setMsgBody(String.format("Please verify using this OTP: %s. It is valid for the next 5 minutes.", otp));
//                        mailBody.setSubject("Verification OTP");
//                        emailService.sendSimpleMail(mailBody);
//
//                        responseMessage = "Verification Pending";
//                    }
//                }else{
//                    responseMessage = "Invalid User";
//                }
//            }
//
//            return responseMessage;
//        } else {
//            return "Login Needed";
//        }
    }

    public LoginResponse freshLogin(LoginRequest loginRequest, HttpServletRequest request, String ip, String userAgent, String deviceId, Boolean freshLogin) throws JOSEException {
        String email = loginRequest.getEmail();
        String pass = loginRequest.getPass();

        LoginResponse response = new LoginResponse();

        String passHash = encoder.encode(pass);
        UserEntity user = userRepository.findByEmail(email);

        if(user == null){
            //return string user not found
            response.setJwe(null);
            response.setRefreshToken(null);
            response.setEmail(null);
            response.setMessage("User Not Found");
        } else {
            Boolean match = passHash.equals(user.getPassword());
            if(match){
                //new jwe creation automatically updates the secret in cache
                String newJwe = createJWE(email,ip, deviceId);
                //if existing refreshtoken in cache and set existing one as revoked in db (already done in the pre-login auth filter
                String newRefreshToken = createRefreshToken();
                //create new jwe tokens and refresh tokens and set as cookies and also set in dbs
                Cookie jweCookie = new Cookie("access_token", newJwe);
                jweCookie.setHttpOnly(true);
                jweCookie.setSecure(false); //TODO: Set true for prod
                jweCookie.setPath("/");
                jweCookie.setMaxAge(15 * 60);

                //create refresh token object
                RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
                refreshTokenEntity.setToken(newRefreshToken);
                refreshTokenEntity.setExpiresAt(Instant.now().plus(Duration.of(7, ChronoUnit.DAYS)));
                refreshTokenEntity.setUser(user);
                refreshTokenEntity.setIp_addr(ip);
                refreshTokenEntity.setUserAgent(userAgent);
                log.info("Refresh Token obj formed: {}", refreshTokenEntity);

                //refresh token cookie
                Cookie refreshCookie = new Cookie("refresh_token", newRefreshToken);
                refreshCookie.setHttpOnly(true);
                refreshCookie.setSecure(false); //TODO: Set true for prod
                refreshCookie.setPath("/");
                refreshCookie.setMaxAge(60 * 60 * 24 * 7);

                response.setJwe(jweCookie);
                response.setRefreshToken(refreshCookie);
                response.setEmail(email);
                response.setMessage("Successful Login");

                redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set("refresh:"+email+":"+deviceId, newRefreshToken);

                rtrepository.save(refreshTokenEntity); //TODO: make it an async process using rabbitmq

            } else {
                //return string invalid credentials
                response.setJwe(null);
                response.setRefreshToken(null);
                response.setEmail(null);
                response.setMessage("Invalid Credentials");
            }
        }

        return response;
    }

//    //modify this for use in login flow
//    public String userLogin(LoginRequest loginReq, HttpServletRequest httpReq, String ip, String userAgent, String deviceId) throws JOSEException {
//        String email = loginReq.getEmail();
//        String pass = loginReq.getPass();
//
//        String loginPassHash = encoder.encode(pass);
//        UserEntity user = userRepository.findByEmail(email);
//        if(user != null){
//            if(loginPassHash.equals(user.getPassword())){
//                //create jwe and refresh token
//                String jweToken = createJWE(email, ip, deviceId);
//                String refreshToken = createRefreshToken();
//                RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
//                refreshTokenEntity.setToken(refreshToken);
//                refreshTokenEntity.setExpiresAt(Instant.now().plus(Duration.of(7, ChronoUnit.DAYS)));
//                refreshTokenEntity.setUser(user);
//                refreshTokenEntity.setIp_addr(ip);
//                refreshTokenEntity.setUserAgent(userAgent);
//                log.info("Refresh Token obj formed: {}", refreshTokenEntity);
//
//                //save refresh token in the db TODO: Should go in the queued process
//                RefreshTokenEntity rtSaved = rtrepository.save(refreshTokenEntity);
//                log.info("Refresh Token saved successfully");
//
//                return "Success";
//            } else {
//                return "Invalid Credentials";
//            }
//        } else {
//            return "Invalid Credentials";
//        }
//    }

    private boolean validatePass(String password){
        log.info("inside validating password: {}", password);
        String regex = "^(?=.*[A-Z])(?=.*\\d)(?=.*[@#]).{8,}$";
        return Pattern.matches(regex, password);
    }

    private String createJWE(String email, String ip, String deviceId) throws JOSEException {

        log.info("inside jwe create for email : {}", email);

        Instant now = Instant.now();
        JWTClaimsSet claimsObj = new JWTClaimsSet.Builder()
                .claim("email", email)
                .claim("iat",now.toString())
                .claim("eat", now.plus(Duration.of(15, ChronoUnit.MINUTES)).toString())
                .build();

        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(claimsObj.toJSONObject())
        );

        String secret = secretGenerator();
        log.info("secret generated: {}", secret);
        redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set("jweSecret:"+ip+":"+deviceId, secret);
        jwe.encrypt(new DirectEncrypter(Base64.getDecoder().decode(secret)));

        String jweEncrypt = jwe.serialize();

        log.info("jwe gotten: {}", jweEncrypt);

        return jweEncrypt;
    }

    private String secretGenerator(){
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        return Base64.getEncoder().encodeToString(secret);
    }

    private String createRefreshToken(){
        byte[] refreshSecret = new byte[32];
        new SecureRandom().nextBytes(refreshSecret);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshSecret);

        return argon2.hash(9, 65536, 4, token);
    }

    @Transactional
    public void markUserVerified(String email, Boolean status) {
        userRepository.updateVerificationStatusByEmail(email, status);
    }
}
