package com.starter.backend.annotation.docs;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Hidden
@Parameter(in = ParameterIn.HEADER, hidden = true)
@Retention(RetentionPolicy.RUNTIME)
public @interface HideParam {
    
}
