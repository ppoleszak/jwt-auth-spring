package com.poleszak.jwtauthspring.config;

import org.springframework.security.config.web.server.ServerHttpSecurity;

public interface JwtPathConfigurer {
    void configure(ServerHttpSecurity http);
}
