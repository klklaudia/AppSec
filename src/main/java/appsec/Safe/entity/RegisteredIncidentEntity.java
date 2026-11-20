package appsec.Safe.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(
    name = "registered_incidents",
    indexes = {
        @Index(name = "idx_registered_incidents_ip", columnList = "ip")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisteredIncidentEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "incident_id")
    private Integer incidentId;

    @Column(name = "ip", length = 50, nullable = false)
    private String ip;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "incident_type_id", nullable = false)
    private IncidentTypeEntity incidentType;

    @Column(name = "blocked_until")
    private LocalDateTime blockedUntil;

    @Column(name = "details", length = 255)
    private String details;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
}