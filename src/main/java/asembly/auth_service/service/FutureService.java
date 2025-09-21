package asembly.auth_service.service;

import asembly.dto.auth.AuthRequest;
import asembly.dto.auth.AuthResult;
import asembly.dto.auth.ValidResponse;
import asembly.util.GeneratorId;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class FutureService {

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;
    private final Map<String, CompletableFuture<AuthResult>> pending = new ConcurrentHashMap<>();

    public CompletableFuture<AuthResult> auth(String username, String password, String topic)
    {
        String futureKey = GeneratorId.generateShortUuid();

        CompletableFuture<AuthResult> future = new CompletableFuture<>();

        var request = new AuthRequest(
                futureKey, username, password);

        pending.put(futureKey, future);

        kafkaTemplate.send(topic, request);

        return future;
    }

    @KafkaListener(topics = "auth-responses", containerFactory = "userListener")
    public void handleValidationResponse(@Payload ValidResponse response)
    {
        var future = pending.remove(response.correlationId());
        if(future != null)
            future.complete(response.result());
    }

}
