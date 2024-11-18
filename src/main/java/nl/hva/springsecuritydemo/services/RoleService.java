package nl.hva.springsecuritydemo.services;

import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import java.util.UUID;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import nl.hva.springsecuritydemo.models.user.User;
import nl.hva.springsecuritydemo.models.user.UserRole;
import nl.hva.springsecuritydemo.repositories.RoleRepository;
import nl.hva.springsecuritydemo.repositories.UserRepository;
import org.springframework.stereotype.Service;

import static nl.hva.springsecuritydemo.models.user.UserRole.ROLE_ADMIN_NAME;
import static nl.hva.springsecuritydemo.models.user.UserRole.ROLE_PREFIX;
import static nl.hva.springsecuritydemo.models.user.UserRole.ROLE_USER_NAME;


@Transactional
@Service
@RequiredArgsConstructor
public class RoleService {

    private final RoleRepository roleRepo;
    private final UserRepository userRepo;

    @PostConstruct
    public void init() {
        checkIfRoleExists(
                ROLE_PREFIX + ROLE_USER_NAME,
                () -> roleRepo.save(new UserRole(ROLE_PREFIX + ROLE_USER_NAME))
        );
        checkIfRoleExists(
                ROLE_PREFIX + ROLE_ADMIN_NAME,
                () -> roleRepo.save(new UserRole(ROLE_PREFIX + ROLE_ADMIN_NAME))
        );
    }

    public User addUserRoleToUserById(UUID userId) {
        User user = userRepo.getReferenceById(userId);

        roleRepo.findByAuthorityEquals(ROLE_PREFIX + ROLE_USER_NAME)
                .ifPresent(user::addRole);

        return userRepo.save(user);
    }

    public User addAdminRoleToUserById(UUID userId) {
        User user = userRepo.getReferenceById(userId);

        roleRepo.findByAuthorityEquals(ROLE_PREFIX + ROLE_ADMIN_NAME)
                .ifPresent(user::addRole);

        return userRepo.save(user);
    }

    private void checkIfRoleExists(
            String authority,
            Supplier<? extends UserRole> ifAbsent
    ) {
        roleRepo.findByAuthorityEquals(authority).orElseGet(ifAbsent);
    }

}