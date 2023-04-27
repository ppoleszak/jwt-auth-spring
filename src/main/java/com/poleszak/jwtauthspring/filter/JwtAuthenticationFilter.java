package com.poleszak.jwtauthspring.filter;

import com.poleszak.jwtauthspring.service.JwtService;
import com.poleszak.jwtauthspring.service.UserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final ServerSecurityContextRepository securityContextRepository;

    @Override
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        String jwtToken;
        String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        jwtToken = authHeader.substring(7);
        username = jwtService.extractUsername(jwtToken);

        if (username != null) {
            return userDetailsService.loadUserByUsername(username)
                    .filter(userDetails -> jwtService.isTokenValid(jwtToken, userDetails))
                    .flatMap(userDetails -> {
                        Authentication authentication = new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());
                        return securityContextRepository.save(exchange, new SecurityContextImpl(authentication))
                                .then(chain.filter(exchange));
                    }).switchIfEmpty(chain.filter(exchange));
        }

        return chain.filter(exchange);
    }
}
