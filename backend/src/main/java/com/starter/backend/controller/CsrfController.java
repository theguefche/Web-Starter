package com.starter.backend.controller;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;

import com.starter.backend.annotation.controllers.RestApiController;
import com.starter.backend.annotation.docs.HideParam;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.links.Link;
import io.swagger.v3.oas.annotations.links.LinkParameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

@RestApiController
public class CsrfController {

    @GetMapping("/csrf/token")
    public CsrfToken csrf(@HideParam CsrfToken token) {
        return token;
    }

}
