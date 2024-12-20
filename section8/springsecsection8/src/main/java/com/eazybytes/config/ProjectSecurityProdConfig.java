package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors(corsConfig  -> corsConfig.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true); // user 인증 정보나 쿠키 정보 수락
                        config.setAllowedHeaders(Collections.singletonList("*")); // 모든 종류의 헤더 수락 가능
                        config.setMaxAge(3600L); //3600초 동안 캐싱
                        return config;
                    }
                }))
                .sessionManagement(smc -> smc.invalidSessionUrl("/invalidSession") // 세션 만료, 유효하지 않은 세션일때 해당 페이지로 리다이렉트
                        .maximumSessions(1).maxSessionsPreventsLogin(true).expiredUrl("/sessionExpired")) // 세션갯수 제한, PreventLogin을 true로 하면 기본 세션 유지 두번째로 로그인하는 세션 무시
                .requiresChannel(rcc -> rcc.anyRequest().requiresSecure()) // Only Accept HTTPS
                .csrf(csrfConfig -> csrfConfig.disable())
                .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/myAccount", "/myBalance", "/myLoans", "/myCards", "/user").authenticated()
                .requestMatchers("/contact", "/notices", "/error", "/register", "/invalidSession").permitAll());
        http.formLogin(withDefaults());
        // EntryPoint 설정
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        // 전역 EntryPoint 설정 (로그인 흐름 httpBasic 이외에도 다른 곳에서 발생할 수 있는 오류 처리)
        // http.exceptionHandling(ehc -> ehc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));

        // AccessDeniedHandler 설정. 자체 UI를 제공하는 상황에서는 .accessDeniedPage("/page") 처럼 설정
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // createDelegatingPasswordEncoder를 사용하면 알맞게 비밀번호를 인코딩해서 제공해줌
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * SpringSecurity 6.3 부터 도입
     * 안전한 비밀번호인지 체크
     */
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
