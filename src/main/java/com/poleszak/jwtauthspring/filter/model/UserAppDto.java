package com.poleszak.jwtauthspring.filter.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Setter
@Getter
public class UserAppDto implements UserDetails {

    private UUID id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private Role role;
    private List<SimpleGrantedAuthorityDto> authorities;

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public Collection<SimpleGrantedAuthorityDto> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}