package com.starter.backend.exception;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.fasterxml.jackson.core.JsonParseException;
import com.starter.backend.payload.DetailedExceptionResponse;
import com.starter.backend.payload.ExceptionResponse;
import com.starter.backend.service.ExceptionService;

@RestControllerAdvice
public class GlobalExceptionRestHandler {

    @Autowired
    private ExceptionService service;

    @ExceptionHandler({ ResourceNotFoundException.class })
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ExceptionResponse handleNotFound(ResourceNotFoundException exception) {

        ExceptionResponse response = ExceptionResponse.builder()
                .cause(exception.getStackTrace()[0].toString())
                .message(exception.getMessage())
                .trace(service.retreiveDebugTrace(exception.getStackTrace()))
                .build();

        return response;
    }

    // @ExceptionHandler({ NoResourceFoundException.class })
    // @ResponseStatus(HttpStatus.NOT_FOUND)
    // public ExceptionResponse handleNotFoundEndpoint(NoResourceFoundException
    // exception) {

    // ExceptionResponse response = ExceptionResponse.builder()
    // .cause("Unresolved target path !")
    // .message(exception.getMessage())
    // .trace(service.retreiveDebugTrace(exception.getStackTrace()))
    // .build();

    // return response;
    // }

    @ExceptionHandler({ BadCredentialsException.class })
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ExceptionResponse handleWrongCredatials(BadCredentialsException exception) {

        ExceptionResponse response = ExceptionResponse.builder()
                .cause("Unable To Find Account")
                .message("Wrong email/password !")
                .trace(service.retreiveDebugTrace(exception.getStackTrace()))
                .build();

        return response;

    }

    // @ExceptionHandler({ Exception.class })
    // @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    // public ExceptionResponse handleUnexpectedErrors(Exception exception) {

    // ExceptionResponse response = ExceptionResponse.builder()
    // .cause(exception.getMessage())
    // .message(exception.getClass().getName())
    // .trace(service.retreiveDebugTrace(exception.getStackTrace()))
    // .build();

    // return response;
    // }

    @ExceptionHandler({ JsonParseException.class, HttpMessageNotReadableException.class })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ExceptionResponse handleJson(JsonParseException exception) {

        ExceptionResponse response = ExceptionResponse.builder()
                .cause(exception.getMessage())
                .message("Invalid JSON Object !")
                .trace(service.retreiveDebugTrace(exception.getStackTrace()))
                .build();

        return response;
    }

    @ExceptionHandler({ MethodArgumentNotValidException.class })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ExceptionResponse handleObjectConversion(MethodArgumentNotValidException exception) {

        BindingResult bindingResult = exception.getBindingResult();
        List<FieldError> fieldErrors = bindingResult.getFieldErrors();

        List<String> errorMessages = new ArrayList<>();
        for (FieldError fieldError : fieldErrors) {
            String fieldName = fieldError.getField();
            String errorMessage = fieldError.getDefaultMessage();
            errorMessages.add("'" + fieldName + "': " + errorMessage);
        }

        DetailedExceptionResponse response = DetailedExceptionResponse.builder()
                .cause("Cannot Convert RequestBody To " + exception.getObjectName() + " : Invalid Object")
                .message("Invalid Information !")
                .trace(service.retreiveDebugTrace(exception.getStackTrace()))
                .details(errorMessages)
                .build();

        return response;
    }
}
