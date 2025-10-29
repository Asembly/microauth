package asembly.auth_service.service;

import asembly.auth_service.client.UserClient;
import asembly.auth_service.config.EnvConfig;
import asembly.auth_service.exception.ErrorResponseParser;
import asembly.dto.auth.AuthRequest;
import asembly.dto.auth.AuthResponse;
import asembly.dto.auth.token.AccessResponse;
import asembly.dto.user.UserCreateRequest;
import asembly.dto.user.UserResponse;
import asembly.exception.PasswordNotRequiredException;
import asembly.exception.UserNotFoundException;
import asembly.util.Jwt;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.auth.InvalidCredentialsException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AuthService {

    @Autowired
    private RefreshService refreshService;

    @Autowired
    private EnvConfig envConfig;

    @Autowired
    private ErrorResponseParser parser;

    @Autowired
    private UserClient userClient;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public ResponseEntity<?> signIn(AuthRequest dto){
        var user = userClient.getUserByUsername(dto.username()).getBody();

        if (user == null)
            throw new UserNotFoundException();

        if (!passwordEncoder.matches(dto.password(), user.password()))
            throw new PasswordNotRequiredException();
        return authResponse(user);
    }

    public ResponseEntity<?> signUp(AuthRequest dto) throws InvalidCredentialsException {

        if(dto.username().length() < 6)
            throw new InvalidCredentialsException("Username length is too short");
        if(dto.password().length() < 8)
            throw new InvalidCredentialsException("Password length is too short");

        return userClient.create(new UserCreateRequest(
                dto.username(),
                passwordEncoder.encode(dto.password()))
        );
    }

    public ResponseEntity<AuthResponse> authResponse(UserResponse dto)
    {
        var refresh = refreshService.refreshTokenCheck(dto.id());
        var access = Jwt.genJwt(dto.username(), envConfig.secret, envConfig.exp_access);

        return ResponseEntity.ok(new AuthResponse(
                dto.id(),
                dto.username(),
                new AccessResponse(access, Jwt.getExpiresAt(access, envConfig.secret).getTime()),
                refresh
        ));
    }
}
