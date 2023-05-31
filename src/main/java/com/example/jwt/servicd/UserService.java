package com.example.jwt.servicd;


import com.example.jwt.jwt.JwtTokenProvider;
import com.example.jwt.mapper.UserMapper;
import com.example.jwt.model.UserRecord;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.request.AuthRequest;
import com.example.jwt.request.UserCreateRequest;
import com.example.jwt.response.AuthUserResponse;
import com.example.jwt.response.UserInfoResponse;
import com.example.jwt.response.UserResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.TriConsumer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserService {

    private final UserDetailService userDetailService;
    private final UserRepository userRepository;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    public UserService(UserDetailService userDetailService, UserRepository userRepository, JwtTokenProvider tokenProvider, AuthenticationManager authenticationManager, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userDetailService = userDetailService;
        this.userRepository = userRepository;
        this.tokenProvider = tokenProvider;
        this.authenticationManager = authenticationManager;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    private AuthUserResponse getAuthResponse(UserResponse user, String username, String password, Collection<? extends GrantedAuthority> authorities) throws RuntimeException {
        UserRecord userRecord = userRepository.findByDocument(username).orElseThrow(() -> new RuntimeException("User not found"));
        if (!user.isEnabled() || !user.isAccountNonLocked() || !user.isEnable()) {
            throw new RuntimeException("User is not active");
        }
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        username,
                        password,
                        authorities
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserResponse userDetails = (UserResponse) authentication.getPrincipal();
        AuthUserResponse.AuthUserResponseBuilder authResponse = AuthUserResponse.builder()
                .userInfo(new UserInfoResponse(userRecord.getId(), userRecord.getFirstName()))
                .accessToken(tokenProvider.createToken(authentication))
                .provider("JDBC")
                .accountCreated(true);

        return authResponse.build();
    }

    public UserRecord create(UserCreateRequest request) throws RuntimeException{
        Optional<UserRecord> userRecord = userRepository.findByDocumentOrEmail(request.getDocument(), request.getEmail());
        if (userRecord.isPresent()) {
            throw new RuntimeException("User already exists");
        }
        if (!request.getPassword().equals(request.getPasswordConfirm())) {
            throw new RuntimeException("Password and password confirm not match");
        }
        return userRepository.save(UserMapper.mapToSave(request, bCryptPasswordEncoder(request.getPassword())));
    }

    private String bCryptPasswordEncoder(String password) {
        return bCryptPasswordEncoder.encode(password);
    }

    public UserRecord findById(long id){
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    }

    public List<UserRecord> findAll() {
        return userRepository.findAll();
    }

    public UserRecord findByDocument(String document) {
        return userRepository.findByDocument(document).orElseThrow(() -> new RuntimeException("User not found"));
    }

    private final TriConsumer<AuthRequest, UserDetails, String> validateUserPassword = (request, user, message) -> {
        if (!bCryptPasswordEncoderMatch(request.getPassword(), user.getPassword())) {
            throw new RuntimeException(message);
        }
    };

    public Boolean getValidationOtp(String otp, long id) {
        Optional<UserRecord> user = userRepository.findByIdAndCodeOtp(id, otp);
        log.info("Inside Otp: {}", otp);
        if (otp.equals(user.get().getCodeOtp())) {
            if (user.get().getExpirationOtp().isAfter(LocalDateTime.now())) {
                return true;
            }
        }
        return false;
    }

    private boolean bCryptPasswordEncoderMatch(String rawPassword, String encodePassword) {
        return bCryptPasswordEncoder.matches(rawPassword, encodePassword);
    }

    public AuthUserResponse signIn(AuthRequest authRequest) throws Exception {
        log.info("Begin signIn UserService::signIn AuthRequest {}", authRequest);
        userDetailService.setFlag("CLIENT");
        UserResponse user = (UserResponse) userDetailService.loadUserByUsername(authRequest.getUsername());
        log.info("user::signIn {}", user.toString());
        validateUserPassword.accept(authRequest, user, "Invalid password");
        AuthUserResponse userResponse = getAuthResponse(user, authRequest.getUsername(), authRequest.getPassword(), user.getAuthorities());
        return userResponse;
    }

}
