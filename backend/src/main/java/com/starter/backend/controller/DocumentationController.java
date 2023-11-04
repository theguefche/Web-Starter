package com.starter.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;

import com.starter.backend.annotation.controllers.DocumentationApiController;

@DocumentationApiController
public class DocumentationController {
    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
