package com.starter.backend.payload.response;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@Data
@SuperBuilder
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ExceptionResponse {
 
    private String cause;
    private String trace;
    private String message;
}
