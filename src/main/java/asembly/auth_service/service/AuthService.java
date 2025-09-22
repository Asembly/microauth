package asembly.auth_service.service;

import asembly.auth_service.config.EnvConfig;
import asembly.dto.auth.AuthRequest;
import asembly.dto.auth.AuthResponse;
import asembly.dto.auth.AuthResult;
import asembly.dto.auth.AuthStatus;
import asembly.dto.auth.token.AccessResponse;
import asembly.session.UserSessionInfo;
import asembly.util.Jwt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
public class AuthService {

    @Autowired
    private FutureService futureService;
    @Autowired
    private RefreshService refreshService;
    @Autowired
    private EnvConfig envConfig;

    public static UserSessionInfo userSession;

    public CompletableFuture<ResponseEntity<?>> signIn(AuthRequest dto){
        return futureService.auth(dto.username(), dto.password(), "signin-requests")
                .orTimeout(5, TimeUnit.SECONDS)
                .exceptionally(ex -> {
                    if(ex instanceof TimeoutException)
                    {
                        return new AuthResult(
                                AuthStatus.TIMEOUT_SERVER,
                                null,
                                null
                        );
                    }else{
                        return new AuthResult(
                                AuthStatus.INTERNAL_SERVER_ERROR,
                                null,
                                null
                        );
                    }
                })
                .thenApply(result -> {
                    switch(result.status())
                    {
                        case VALID -> {
                            userSession = new UserSessionInfo(dto.username(), dto.password());
                            return authResponse(result.user_id(), result.username());
                        }
                        case USER_NOT_FOUND -> {
                            return ResponseEntity
                                    .status(HttpStatus.NOT_FOUND)
                                    .body("User not found");
                        }
                        case INVALID_CREDENTIALS -> {
                            return ResponseEntity
                                    .status(HttpStatus.UNAUTHORIZED)
                                    .body("Invalid credentials");
                        }
                        case TIMEOUT_SERVER -> {
                            return ResponseEntity
                                    .status(HttpStatus.GATEWAY_TIMEOUT)
                                    .body("Server timeout");
                        }
                        default -> {
                            return ResponseEntity
                                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                                    .body("Internal server error");
                        }
                    }
                });
    }

    public CompletableFuture<ResponseEntity<?>> signUp(AuthRequest dto){
        return futureService.auth(dto.username(), dto.password(), "signup-requests")
                .orTimeout(5, TimeUnit.SECONDS)
                .exceptionally(ex -> {
                    if(ex instanceof TimeoutException)
                    {
                        return new AuthResult(
                                AuthStatus.TIMEOUT_SERVER,
                                null,
                                null
                        );
                    }else{
                        return new AuthResult(
                                AuthStatus.INTERNAL_SERVER_ERROR,
                                null,
                                null
                        );
                    }
                })
                .thenApply(result -> {
                    switch(result.status())
                    {
                        case VALID -> {
                            return ResponseEntity
                                    .status(HttpStatus.OK)
                                    .body("Registration successful");
                        }
                        case USER_ALREADY_EXIST -> {
                            return ResponseEntity
                                    .status(HttpStatus.BAD_REQUEST)
                                    .body("User already exits");
                        }
                        case INVALID_CREDENTIALS -> {
                            return ResponseEntity
                                    .status(HttpStatus.UNAUTHORIZED)
                                    .body("Invalid credentials");
                        }
                        case TIMEOUT_SERVER -> {
                            return ResponseEntity
                                    .status(HttpStatus.GATEWAY_TIMEOUT)
                                    .body("Server timeout");
                        }
                        default -> {
                            return ResponseEntity
                                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                                    .body("Internal server error");
                        }
                    }
                });
    }

    public ResponseEntity<AuthResponse> authResponse(String user_id, String username)
    {
        var refresh = refreshService.refreshTokenCheck(user_id);

        var access = Jwt.genJwt(username, envConfig.secret, envConfig.exp_access);

        return ResponseEntity.ok(new AuthResponse(
                user_id,
                username,
                new AccessResponse(access, Jwt.getExpiresAt(access, envConfig.secret).getTime()),
                refresh
        ));
    }
}
