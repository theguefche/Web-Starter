package com.starter.backend.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;

import com.starter.backend.annotation.controllers.RestApiController;

import jakarta.servlet.http.HttpServletResponse;

@RestApiController
public class V {

    @GetMapping("/v")
    public String g() {
        String version = org.springframework.security.core.SpringSecurityCoreVersion.class.getPackage()
                .getImplementationVersion();
        return version;

    }

    @GetMapping("/v/secure-cookies")
    public ResponseEntity<?> x(HttpServletResponse response) {
        ResponseCookie c = ResponseCookie.from("secure", "secured").path("/").maxAge(-1).secure(true).build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, c.toString()).body("done");

    }

    @GetMapping("/v/not-secure-cookies")
    public ResponseEntity<?> y(HttpServletResponse response) {
        ResponseCookie c = ResponseCookie.from("not-secure", "not-secured").path("/").maxAge(-1).secure(false).build();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, c.toString()).body("done");

    }

}
