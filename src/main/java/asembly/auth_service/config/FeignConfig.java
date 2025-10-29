package asembly.auth_service.config;

import asembly.auth_service.client.CustomErrorDecoder;
import feign.RequestInterceptor;
import feign.codec.ErrorDecoder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
@Configuration
public class FeignConfig {

    @Bean
    public ErrorDecoder errorDecoder() {
        return new CustomErrorDecoder();
    }

    @Bean
    public RequestInterceptor authInterceptor() {
        return requestTemplate -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if(auth != null && auth.getCredentials() instanceof String){
                String token = (String)auth.getCredentials();
                log.info(token);
                requestTemplate.header("Authorization", "Bearer " + token);
                log.info("{}",requestTemplate.headers());
            }
        };
    }
}
