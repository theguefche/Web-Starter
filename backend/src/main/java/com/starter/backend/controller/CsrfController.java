package com.starter.backend.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.starter.backend.annotation.controllers.RestApiController;

@RestApiController
public class CsrfController {

    @GetMapping("/csrf/token")
    public CsrfToken csrf(CsrfToken token) {
        return token;
    }

}
