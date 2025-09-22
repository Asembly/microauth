package asembly.auth_service.service;

import asembly.auth_service.config.EnvConfig;
import asembly.auth_service.entity.RefreshToken;
import asembly.auth_service.mapper.TokenMapper;
import asembly.auth_service.repository.RefreshRepository;
import asembly.dto.auth.token.AccessResponse;
import asembly.dto.auth.token.RefreshResponse;
import asembly.util.GeneratorId;
import asembly.util.Jwt;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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


    @Autowired
    private RefreshRepository refreshTokenRepository;
    @Autowired
    private TokenMapper tokenMapper;
    @Autowired
    private EnvConfig envConfig;

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
                    Timestamp.from(Instant.now().plusMillis(envConfig.exp_refresh)).getTime()
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

        log.info("JWT SECRET _-------------- {}", envConfig.secret);

        String newJwt = Jwt.genJwt(
                AuthService.userSession.username(),
                envConfig.secret,
                envConfig.exp_access);

        if(newJwt == null)
            return ResponseEntity.badRequest().body("TODO");

        return ResponseEntity.ok(new AccessResponse(
                newJwt,
                Jwt.getExpiresAt(newJwt, envConfig.secret).getTime()));
    }

    public boolean isTokenExpired(RefreshToken token) {
        return Time.from(Instant.now()).getTime() > token.getExpires_at();
    }
}
