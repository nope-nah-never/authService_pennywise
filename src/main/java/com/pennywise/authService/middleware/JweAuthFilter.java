package com.pennywise.authService.middleware;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.pennywise.authService.configs.RedisConfig;
import com.pennywise.authService.db_entities.RefreshTokenEntity;
import com.pennywise.authService.repositories.RefreshTokenRepository;
import com.pennywise.authService.services.AuthService;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;

@Component
public class JweAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JweAuthFilter.class);

    @Autowired
    public RedisConfig redisConfig;

    Argon2 argon2 = Argon2Factory.create();

    @Autowired
    public RefreshTokenRepository rtrepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String deviceId = request.getHeader("X-Device-Id");
        String clientIp = getIp(request);

        Cookie[] cookies = request.getCookies();

        String jweToken = null;

        if(cookies != null){
            for (Cookie cookie: cookies){
                if ("access_token".equals(cookie.getName())){
                    jweToken = cookie.getValue();
                    break;
                }
            }
        }

        if(jweToken!= null){
            try{
                String secret = redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().get("jweSecret:"+clientIp+":"+deviceId).toString();
                JWEObject jweObject = JWEObject.parse(jweToken);

                jweObject.decrypt(new DirectDecrypter(
                        Base64.getDecoder().decode(secret)
                ));

                JWTClaimsSet claims = JWTClaimsSet.parse(jweObject.getPayload().toJSONObject());

                String userEmail = claims.getClaimAsString("email");
                Instant expiryTime = Instant.parse((String) claims.getClaimAsString("eat"));

                String refreshTokenCache = redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().get("refresh:"+userEmail+":"+deviceId).toString();
                ObjectMapper mapper  = new ObjectMapper();
                RefreshTokenEntity refreshTokenObj = mapper.readValue(refreshTokenCache, RefreshTokenEntity.class);

                if(Instant.now().isBefore(expiryTime)){
                    //TODO: HAPPY FLOW
                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userEmail,null, List.of());
                    SecurityContextHolder.getContext().setAuthentication(auth);

                } else if(refreshTokenObj.getExpiresAt().isAfter(Instant.now()) || !refreshTokenObj.getRevoked()){
                    String newJwe = createJWE(userEmail, clientIp, deviceId);
                    String newRefreshToken = createRefreshToken();

                    Instant usedTime = Instant.now();
                    refreshTokenObj.setUsedAt(usedTime);
                    refreshTokenObj.setToken(newRefreshToken);

                    redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set("refresh:"+userEmail+":"+deviceId, mapper.writeValueAsString(refreshTokenObj));

                    Cookie newJweCookie = new Cookie("access_token", newJwe);
                    newJweCookie.setHttpOnly(true);
                    newJweCookie.setSecure(false); //TODO: Set true for prod
                    newJweCookie.setPath("/");
                    newJweCookie.setMaxAge(15 * 60);
                    response.addCookie(newJweCookie);

                    Cookie newRefreshCookie = new Cookie("refresh_token", newRefreshToken);
                    newRefreshCookie.setHttpOnly(true);
                    newRefreshCookie.setSecure(false); //TODO: Set true for prod
                    newRefreshCookie.setPath("/");
                    long seconds = Duration.between(usedTime, refreshTokenObj.expiresAt).toSeconds();
                    newRefreshCookie.setMaxAge((int) seconds);
                    response.addCookie(newRefreshCookie);

                    rtrepository.updateUsedAtAndTokenHashById(usedTime, newRefreshToken, refreshTokenObj.getId());

                    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userEmail,null, List.of());
                    SecurityContextHolder.getContext().setAuthentication(auth);

                } else {
                    //TODO: set the refresh token as revoked and drop the token from cache
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("Login Needed");
                }

            }catch (Exception e){
                log.error("Exception occurred:", e);
            }
        }

        filterChain.doFilter(request,response);
    }

    private String getIp(HttpServletRequest request){
        String xHeader = request.getHeader("X-Forwarded-For");
        if(xHeader == null || xHeader.isEmpty()){
            return request.getRemoteAddr();
        }
        return xHeader.split(",")[0];
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
        redisConfig.redisTemplate(redisConfig.redisConnectionFactory()).opsForValue().set("jweSecret"+ip+deviceId, secret);
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

}
