package nl.hva.springsecuritydemo.services;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import nl.hva.springsecuritydemo.dtos.user.RegisterDto;
import nl.hva.springsecuritydemo.dtos.user.UpdateDto;
import nl.hva.springsecuritydemo.exceptions.ConflictException;
import nl.hva.springsecuritydemo.exceptions.ResourceNotFound;
import nl.hva.springsecuritydemo.models.user.User;
import nl.hva.springsecuritydemo.repositories.RoleRepository;
import nl.hva.springsecuritydemo.repositories.UserRepository;
import nl.hva.springsecuritydemo.utils.SecurityContextUtil;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;
import java.util.UUID;

import static org.springframework.util.StringUtils.hasLength;
import static org.springframework.util.StringUtils.hasText;


@Service
@Transactional
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

  private final UserRepository userRepository;
  private final PasswordEncoder encoder;
  private final RoleRepository roleRepository;
  private final RoleService roleService;

  /**
   * Returns a user entity, with the provided userName if it exists, otherwise null.
   */
  public User findByUserName(String username) {
    return hasLength(username) ? userRepository.findByUsername(username).orElse(null) : null;
  }

  public User findByEmail(String email) {
    return userRepository.findByEmail(email)
      .orElseThrow(() -> new ResourceNotFound(User.class.getSimpleName(), "email", email));
  }

  public User findById(UUID id) {
    return userRepository.findById(id)
      .orElseThrow(() -> new ResourceNotFound(User.class.getSimpleName(), "id", id.toString()));
  }


  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return userRepository
      .findByUsername(username)
      .orElseThrow(() -> new UsernameNotFoundException(
        String.format("User with username - %s, not found", username)
      ));
  }

  /**
   * Creates a user based on the provided request.
   */
  public User create(RegisterDto req) {
    this.userRepository.findByUsername(req.getUsername()).ifPresent(g -> {
      throw new ConflictException("Username already exists.");
    });

    var user = this.userRepository.save(req.toUser(encoder));

    return roleService.addUserRoleToUserById(user.getId());
  }


  public void remove(User user) {
    this.userRepository.delete(user);
  }

  public User update(UpdateDto updateDto) {
    User user = SecurityContextUtil.getUser();

    updateUsernameIfPresent(updateDto, user);
    updateEmailIfPresent(updateDto, user);
    updatePasswordIfPresent(updateDto, user);

    return userRepository.save(user);
  }

  private void updateUsernameIfPresent(UpdateDto updateDto, User user) {
    Optional.ofNullable(updateDto.getUsername())
      .filter(StringUtils::hasText)
      .ifPresent(user::setUsername);
  }

  private void updateEmailIfPresent(UpdateDto updateDto, User user) {
    Optional.ofNullable(updateDto.getEmail())
      .filter(StringUtils::hasText)
      .ifPresent(user::setEmail);
  }

  private void updatePasswordIfPresent(UpdateDto updateDto, User user) {
    if (hasText(updateDto.getPassword())) user.setPassword(encoder.encode(updateDto.getPassword()));
  }

}
