package com.example.jwt.jwt;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@ConfigurationProperties(prefix = "jwt")
@Data
@Configuration
public class JwtProperties {
    private String key;
    private String secret;
    private int expirationTimeInMinutes;
}
