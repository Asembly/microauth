package asembly.auth_service.client;

import asembly.exception.UserNotFoundException;
import feign.Response;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.common.errors.ResourceNotFoundException;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class CustomErrorDecoder implements ErrorDecoder {

    @Override
    public Exception decode(String methodKey, Response response) {
        HttpStatus status = HttpStatus.valueOf(response.status());
        String responseBody = extractResponseBody(response);

        log.error("Feign client error. Method: {}, Status: {}, Body: {}",
                methodKey, status, responseBody);

        switch (status) {
            case BAD_REQUEST:
                return new IllegalArgumentException("Invalid request: " + responseBody);
            case UNAUTHORIZED:
                return new SecurityException("Unauthorized access");
            case FORBIDDEN:
                return new UserNotFoundException();
            case NOT_FOUND:
                return new ResourceNotFoundException("Resource not found");
            case INTERNAL_SERVER_ERROR:
                return new RuntimeException("Internal server error");
            default:
                return new Exception("Unexpected error: " + responseBody);
        }
    }

    private String extractResponseBody(Response response) {
        if (response.body() == null) {
            return "No response body";
        }

        try {
            return new String(response.body().asInputStream().readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            log.error("Failed to read response body", ex);
            return "Error reading response body";
        }
    }
}