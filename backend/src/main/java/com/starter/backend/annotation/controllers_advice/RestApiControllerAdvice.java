package com.starter.backend.annotation.controllers_advice;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.swagger.v3.oas.annotations.Hidden;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
// @ControllerAdvice
@RestControllerAdvice
@Hidden // hide responses of exceptions
public @interface RestApiControllerAdvice {
}