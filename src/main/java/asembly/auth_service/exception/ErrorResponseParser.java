package asembly.auth_service.exception;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class ErrorResponseParser {

    private final ObjectMapper objectMapper;

    public ErrorResponseParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String extractErrorMessage(String jsonResponse) {
        try {
            JsonNode rootNode = objectMapper.readTree(jsonResponse);
            String message = rootNode.path("message").asText();

            // Обрабатываем вложенный JSON
            if (message != null && message.startsWith("{") && message.endsWith("}")) {
                JsonNode innerNode = objectMapper.readTree(message);
                return innerNode.path("message").asText("External service error");
            }

            return message;

        } catch (Exception e) {
            log.warn("Failed to parse error response: {}", jsonResponse);
            return "Service unavailable";
        }
    }
}
