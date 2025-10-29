package asembly.auth_service.repository;

import asembly.auth_service.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshRepository extends JpaRepository<RefreshToken, String> {
    @Query(value = "select * from refresh_tokens where token = :token", nativeQuery = true)
    public Optional<RefreshToken> findByToken(String token);

    @Query(value = "select * from refresh_tokens where user_id = :user_id", nativeQuery = true)
    public Optional<RefreshToken> findTokenByUserId(String user_id);
}
