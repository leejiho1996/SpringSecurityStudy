package com.eazybytes.config;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.AuthoritiesLoggingAfterFilter;
import com.eazybytes.filter.AuthoritiesLoggingAtFilter;
import com.eazybytes.filter.CsrfCookieFilter;
import com.eazybytes.filter.RequestValidationBeforeFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.*;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;
import java.util.function.Supplier;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName("potato");

        http.cors(corsConfig  -> corsConfig.configurationSource(new CorsConfigurationSourceImpl()))
                .csrf(csrfConfig -> csrfConfig.csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers("/contact", "/register")
                        // withHttpOnlyFalse를 설정하지 않으면 JS가 쿠키 내용을 읽을 수 없다.
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                // BasicAuthenticationFilter가 실행 된 후 CsrfCookieFilter 실행
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
                .securityContext(contextConfig -> contextConfig.requireExplicitSave(false))
                .sessionManagement(smc -> smc.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
//                        .sessionFixation(sfc -> sfc.changeSessionId())
//                        .invalidSessionUrl("/invalidSession")
//                        .maximumSessions(3).maxSessionsPreventsLogin(true))
                .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // Only Accept HTTP
                .authorizeHttpRequests(requests -> requests
//                .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//                .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE", "VIEWACCOUNT")
//                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
//                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                // ROLE_ 접두사를 안붙혀도 됨
                .requestMatchers("/myAccount").hasRole("USER")
                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/myLoans").hasRole("USER")
                .requestMatchers("/myCards").hasRole("USER")
                .requestMatchers("/user").authenticated()
                .requestMatchers("/contact", "/notices", "/error", "/register", "/invalidSession").permitAll());
        http.formLogin(withDefaults());
        // EntryPoint 설정
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }

//    final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
//        private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
//        private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();
//
//        @Override
//        public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
//            /*
//             * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of
//             * the CsrfToken when it is rendered in the response body.
//             */
//            this.xor.handle(request, response, csrfToken);
//            /*
//             * Render the token value to a cookie by causing the deferred token to be loaded.
//             */
//            csrfToken.get();
//        }
//
//        @Override
//        public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
//            String headerValue = request.getHeader(csrfToken.getHeaderName());
//            /*
//             * If the request contains a request header, use CsrfTokenRequestAttributeHandler
//             * to resolve the CsrfToken. This applies when a single-page application includes
//             * the header value automatically, which was obtained via a cookie containing the
//             * raw CsrfToken.
//             *
//             * In all other cases (e.g. if the request contains a request parameter), use
//             * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
//             * when a server-side rendered form includes the _csrf request parameter as a
//             * hidden input.
//             */
//            return (StringUtils.hasText(headerValue) ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
//        }
//    }

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
