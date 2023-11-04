package com.starter.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;

import com.starter.backend.annotation.controllers.RestApiController;

@RestApiController
public class V {

    @GetMapping("/v")
    public String g() {
        String version = org.springframework.security.core.SpringSecurityCoreVersion.class.getPackage()
                .getImplementationVersion();
        return version;
    }
}
