package asembly.auth_service.client;

import asembly.auth_service.config.FeignConfig;
import asembly.dto.user.UserCreateRequest;
import asembly.dto.user.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-client", url = "${feign.service.user-service}", configuration = FeignConfig.class)
public interface UserClient {

    @GetMapping("/users/username/{username}")
    ResponseEntity<UserResponse> getUserByUsername(@PathVariable String username);

    @GetMapping("/users/{id}")
    ResponseEntity<UserResponse> getUserById(@PathVariable String id);

    @PostMapping("/users")
    ResponseEntity<UserResponse> create(@RequestBody UserCreateRequest dto);

}