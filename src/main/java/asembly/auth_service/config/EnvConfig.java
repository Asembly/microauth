package asembly.auth_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class EnvConfig {
    @Value("${spring.jwt.secret}")
    public String secret;
    @Value("${spring.jwt.access.expiration}")
    public Long exp_access;
    @Value("${spring.jwt.refresh.expiration}")
    public Long exp_refresh;
}
