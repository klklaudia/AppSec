package appsec.safe.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "incident_types")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IncidentTypeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "incident_type_id")
    private Integer incidentTypeId;

    @Column(name = "incident_name", length = 30, nullable = false, unique = true)
    private String incidentName;
}