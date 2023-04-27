package com.poleszak.jwtauthspring.config;

import com.poleszak.jwtauthspring.filter.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.springframework.security.config.web.server.SecurityWebFiltersOrder.AUTHENTICATION;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
@EnableReactiveMethodSecurity
public class JwtSecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final JwtPathConfigurer jwtPathConfigurer;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        http
                .csrf()
                .disable()
                .authorizeExchange()
                .and()
                .addFilterAt(jwtAuthFilter, AUTHENTICATION);

        jwtPathConfigurer.configure(http);
        return http.build();
    }
}