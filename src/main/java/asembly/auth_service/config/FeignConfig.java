package asembly.auth_service.config;

import asembly.auth_service.client.CustomErrorDecoder;
import feign.codec.ErrorDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignConfig {

    @Bean
    public ErrorDecoder feignErrorDecoder()
    {
       return new CustomErrorDecoder();
    }
}
