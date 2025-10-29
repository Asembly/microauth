package asembly.auth_service.controller;


import asembly.auth_service.service.AuthService;
import asembly.auth_service.service.RefreshService;
import asembly.dto.auth.AuthRequest;
import org.apache.http.auth.InvalidCredentialsException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<?>signUp(@RequestBody AuthRequest user) throws InvalidCredentialsException {
        return authService.signUp(user);
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(@RequestBody AuthRequest userDto){
        return authService.signIn(userDto);
    }

}
