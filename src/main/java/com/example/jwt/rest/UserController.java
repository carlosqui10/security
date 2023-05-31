package com.example.jwt.rest;



import com.example.jwt.model.UserRecord;
import com.example.jwt.request.AuthRequest;
import com.example.jwt.request.UserCreateRequest;
import com.example.jwt.servicd.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.springframework.http.ResponseEntity.ok;

@Slf4j
@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public UserRecord create(@RequestBody UserCreateRequest request){
        return userService.create(request);
    }

    @GetMapping("/otp/{id}")
    public Boolean getAuthOtp(@RequestParam String otp,@PathVariable long id){
        return userService.getValidationOtp(otp, id);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@Validated @RequestBody AuthRequest authRequest) throws Exception {
        log.info("Inside UserController::signIn AuthRequest: {} ", authRequest.toString());
        return ok().body(userService.signIn(authRequest));
    }

    @GetMapping("/{id}")
    public UserRecord findById(@PathVariable long id)  {
        return userService.findById(id);
    }

    @GetMapping("/document")
    public UserRecord findByDocument(@RequestParam String document) throws Exception {
        return userService.findByDocument(document);
    }

    @GetMapping
    public List<UserRecord> findAll() {
        return userService.findAll();
    }

}
