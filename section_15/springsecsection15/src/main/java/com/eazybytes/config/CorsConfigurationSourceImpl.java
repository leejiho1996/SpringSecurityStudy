package com.eazybytes.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

public class CorsConfigurationSourceImpl implements CorsConfigurationSource {
    @Override
    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        config.setAllowedMethods(Collections.singletonList("*"));
        config.setAllowCredentials(true); // user 인증 정보나 쿠키 정보 수락
        config.setAllowedHeaders(Collections.singletonList("*")); // 모든 종류의 헤더 수락 가능
        config.setExposedHeaders(Arrays.asList("Authorization")); // UI서버에 헤더 전송 가능
        config.setMaxAge(3600L); //3600초 동안 캐싱
        return config;
    }
}
