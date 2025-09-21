package asembly.auth_service.service;

import asembly.auth_service.entity.RefreshToken;
import asembly.auth_service.mapper.TokenMapper;
import asembly.auth_service.repository.RefreshRepository;
import asembly.auth_service.security.JwtService;
import asembly.dto.auth.token.AccessResponse;
import asembly.dto.auth.token.RefreshResponse;
import asembly.util.GeneratorId;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.sql.Time;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@AllArgsConstructor
@NoArgsConstructor
public class RefreshService {

    @Value("${spring.jwt.refresh.expiration}")
    private Long refreshTokenExpiration;

    @Autowired
    private RefreshRepository refreshTokenRepository;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private TokenMapper tokenMapper;

    public ResponseEntity<String> logout(String refresh_token)
    {
        var response = refreshTokenRepository.findByToken(refresh_token).orElseThrow();
        refreshTokenRepository.delete(response);
        return ResponseEntity.ok("User logout.");
    }

    public ResponseEntity<RefreshResponse> generateRefreshToken(String user_id)
    {
        var token = new RefreshToken(
                    GeneratorId.generateShortUuid(),
                    user_id,
                    UUID.randomUUID().toString(),
                    Timestamp.from(Instant.now().plusMillis(refreshTokenExpiration)).getTime()
                );

        refreshTokenRepository.save(token);

        return ResponseEntity.ok(tokenMapper.toTokenResponse(token));
    }
    public RefreshResponse refreshTokenCheck(String user_id)
    {
        var optionalRefresh = refreshTokenRepository.findTokenByUserId(user_id);

        if(optionalRefresh.isEmpty())
            return generateRefreshToken(user_id).getBody();
        else
            return tokenMapper.toTokenResponse(optionalRefresh.get());
    }


    public ResponseEntity<?> updateAccessToken(String refresh_token){
        var token = refreshTokenRepository.findByToken(refresh_token).orElseThrow();

        if(isTokenExpired(token))
        {
            refreshTokenRepository.delete(token);
            return ResponseEntity.badRequest().body("TODO");
        }

        String newJwt = jwtService.genJwt(AuthService.userSession.username());

        if(newJwt == null)
            return ResponseEntity.badRequest().body("TODO");

        return ResponseEntity.ok(new AccessResponse(
                newJwt,
                jwtService.getExpiresAt(newJwt).getTime()));
    }

    public boolean isTokenExpired(RefreshToken token) {
        return Time.from(Instant.now()).getTime() > token.getExpires_at();
    }
}
