package com.example.jwt.response;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
@Slf4j
public class UserResponse implements UserDetails {

    private Long id;
    private String document;
    private String password;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;
    private boolean enable;




    public UserResponse(Long id, String document, String password, boolean enabled,
                        boolean accountNonExpired, boolean credentialsNonExpired,
                        boolean accountNonLocked, boolean enable

    ) {

        if (((document == null) || "".equals(document)) || (password == null)) {
            log.info("UserResponse::signIn {}", id, document, password, enable, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked);
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        }
        this.id = id;
        this.document = document;
        this.password = password;
        this.enabled = enabled;
        this.enable = enable;
        this.accountNonExpired = accountNonExpired;
        this.credentialsNonExpired = credentialsNonExpired;
        this.accountNonLocked = accountNonLocked;
        log.info("UserResponse::signIn {}", id, document, password, enable, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked);
    }


    public UserResponse() {
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.document;
    }
}

