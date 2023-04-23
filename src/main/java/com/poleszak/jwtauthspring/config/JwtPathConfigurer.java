package com.poleszak.jwtauthspring.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public interface JwtPathConfigurer {
    void configure(HttpSecurity http) throws Exception;
}