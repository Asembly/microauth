package asembly.auth_service.mapper;

import asembly.auth_service.entity.RefreshToken;
import asembly.dto.auth.token.RefreshResponse;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TokenMapper {

    RefreshResponse toTokenResponse(RefreshToken refresh);

}
