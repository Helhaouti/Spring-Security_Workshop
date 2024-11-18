package nl.hva.springsecuritydemo.repositories;

import java.util.Optional;
import java.util.UUID;
import nl.hva.springsecuritydemo.models.user.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;


@Repository
public interface RoleRepository extends JpaRepository<UserRole, UUID> {

    @Query("select u from UserRole u where u.authority = ?1")
    Optional<UserRole> findByAuthorityEquals(String authority);

}