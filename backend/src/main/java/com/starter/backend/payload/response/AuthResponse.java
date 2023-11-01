package com.starter.backend.payload.response;

import com.starter.backend.enums.Role;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class AuthResponse {
    private Role role;
    private String email ;
}
