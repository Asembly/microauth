package asembly.auth_service.controller;


import asembly.auth_service.service.AuthService;
import asembly.auth_service.service.RefreshService;
import asembly.dto.auth.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private RefreshService refreshTokenService;

    @PostMapping("/refresh/{token}")
    public ResponseEntity<?> updateAccessToken(@PathVariable String token){
        return refreshTokenService.updateAccessToken(token);
    }

    @DeleteMapping("/logout/{token}")
    public ResponseEntity<String> logout(@PathVariable String token)
    {
        return refreshTokenService.logout(token);
    }

    @PostMapping("/sign-up")
    public CompletableFuture<ResponseEntity<?>> signUp(@RequestBody AuthRequest user) {
        return authService.signUp(user);
    }

    @PostMapping("/sign-in")
    public CompletableFuture<ResponseEntity<?>> signIn(@RequestBody AuthRequest userDto){
        return authService.signIn(userDto);
    }

}
