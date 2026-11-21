package appsec.safe.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Integer roleId;

    @Column(name = "role_name", length = 20, nullable = false, unique = true)
    private String roleName;

    @Column(name = "can_remove_users", nullable = false)
    @Builder.Default
    private boolean canRemoveUsers = false;
}