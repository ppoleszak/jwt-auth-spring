package com.poleszak.jwtauthspring.filter;

import com.poleszak.jwtauthspring.service.JwtService;
import com.poleszak.jwtauthspring.service.UserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        Optional<String> jwtToken = extractJwtToken(authHeader);

        jwtToken.ifPresent(token -> {
            try {
                String username = jwtService.extractUsername(token);
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                    if (jwtService.isTokenValid(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                        authenticationToken.setDetails(new WebAuthenticationDetailsSource()
                                .buildDetails(request)
                        );
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    }
                }
            } catch (Exception e) {
                log.error("Error processing JWT token: {}", e.getMessage(), e);
            }
        });

        filterChain.doFilter(request, response);
    }

    private Optional<String> extractJwtToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith(AUTH_HEADER_PREFIX)) {
            return Optional.empty();
        }
        return Optional.of(authHeader.substring(AUTH_HEADER_PREFIX.length()));
    }
}