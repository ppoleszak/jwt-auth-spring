package com.poleszak.jwtauthspring.service;

import com.poleszak.jwtauthspring.filter.model.UserAppDto;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface UserDetailsProvider extends UserDetailsService {

    UserAppDto loadUserByUsername(String username, String jwtToken) throws UsernameNotFoundException;

    @Override
    default UserAppDto loadUserByUsername(String username) throws UsernameNotFoundException {
        return loadUserByUsername(username, null);
    }
}