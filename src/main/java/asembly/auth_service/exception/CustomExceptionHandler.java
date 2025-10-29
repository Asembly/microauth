package asembly.auth_service.exception;

import asembly.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.InvalidCredentialsException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@Slf4j
@RestControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseError handle(PasswordNotRequiredException exception)
    {
       log.error(exception.getMessage());
       return new ResponseError(HttpStatus.UNAUTHORIZED, exception.getMessage(), LocalDateTime.now());
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseError handle(TokenExpiredException exception)
    {
        log.error(exception.getMessage());
        return new ResponseError(HttpStatus.UNAUTHORIZED, exception.getMessage(), LocalDateTime.now());
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ResponseError handle(TokenNotFoundException exception)
    {
        log.error(exception.getMessage());
        return new ResponseError(HttpStatus.UNAUTHORIZED, exception.getMessage(), LocalDateTime.now());
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ResponseError handle(UserNotFoundException exception)
    {
        log.error(exception.getMessage());
        return new ResponseError(HttpStatus.NOT_FOUND, exception.getMessage(), LocalDateTime.now());
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ResponseError handle(UserAlreadyExistException exception)
    {
        log.error(exception.getMessage());
        return new ResponseError(HttpStatus.FORBIDDEN, exception.getMessage(), LocalDateTime.now());
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseError handle(IllegalArgumentException exception)
    {
        log.error(exception.getMessage());
        return new ResponseError(HttpStatus.BAD_REQUEST, exception.getMessage(), LocalDateTime.now());
    }

    @ExceptionHandler
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseError handle(InvalidCredentialsException exception)
    {
        log.error(exception.getMessage());
        return new ResponseError(HttpStatus.BAD_REQUEST, exception.getMessage(), LocalDateTime.now());
    }
}