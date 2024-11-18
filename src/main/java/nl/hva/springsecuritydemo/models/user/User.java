package nl.hva.springsecuritydemo.models.user;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.userdetails.UserDetails;

import static jakarta.persistence.FetchType.EAGER;


@Entity
@Table(name = "`User`")

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder

@JsonIdentityInfo(
        generator = ObjectIdGenerators.PropertyGenerator.class,
        scope = User.class,
        property = "id"
)
public class User implements UserDetails {

    // TODO: Only include ID, authorities.

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
    @Column(unique = true)
    private String username;
    @Column(unique = true)
    private String email;

    /**
     * Hashed password.
     */
    @JsonIgnore
    private String password;

    @CreationTimestamp
    @Setter(value = AccessLevel.NONE)
    private LocalDateTime createdAt;
    @UpdateTimestamp
    @Setter(value = AccessLevel.NONE)
    private LocalDateTime changedAt;

    @Builder.Default()
    private boolean enabled = true;
    @Builder.Default()
    private boolean accountNonExpired = true;
    @Builder.Default()
    private boolean accountNonLocked = true;
    @Builder.Default()
    private boolean credentialsNonExpired = true;

    @Builder.Default()
    @ManyToMany(fetch = EAGER)
    private Set<UserRole> authorities = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;

        return getId().equals(user.getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }

    public void addRole(UserRole role) {
        if (getAuthorities() == null || !(getAuthorities() instanceof HashSet))
            setAuthorities(new HashSet<>(Objects.requireNonNullElse(getAuthorities(), new HashSet<>())));

        getAuthorities().add(role);
    }

}