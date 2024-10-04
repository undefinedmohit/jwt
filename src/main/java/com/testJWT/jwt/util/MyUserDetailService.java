package com.testJWT.jwt.util;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import java.util.Arrays;

@Service
public class MyUserDetailService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Add roles for each user
        if ("admin".equals(username)) {
            return new User("admin",
                    "password",
                    Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN")));
        } else if ("user".equals(username)) {
            return new User("user",
                    "userpass",
                    Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
        } else if ("manager".equals(username)) {
            return new User("manager",
                    "managerpass",
                    Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER")));
        } else {
            throw new UsernameNotFoundException("User not found");
        }
    }
}

