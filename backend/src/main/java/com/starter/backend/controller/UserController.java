package com.starter.backend.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.starter.backend.annotation.CurrentUser;
import com.starter.backend.exception.ResourceNotFoundException;
import com.starter.backend.model.User;
import com.starter.backend.repository.UserRepository;
import com.starter.backend.security.UserPrincipal;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user/me")
    // @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId())
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", userPrincipal.getId()));
    }

    @GetMapping("/user/hi")
    public String uString() {
        return "hi!";
    }

    @PostMapping("/user")
    public String testCSRF() {
        return "Csrf Protection grants Access";
    }
}
