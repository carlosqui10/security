package com.example.jwt.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "CLIENT")
public class UserRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    private String document;
    private String phone;
    private boolean status;
    private String codeOtp;
    private LocalDateTime createAtOtp;
    private LocalDateTime expirationOtp;


}
