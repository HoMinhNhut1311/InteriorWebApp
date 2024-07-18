package com.hominhnhut.WMN_BackEnd.domain.enity;

import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor

@Entity
@Table(name = "roles")
@FieldDefaults(level = AccessLevel.PRIVATE)

@SqlResultSetMapping(
        name = "RoleDtoResponseMapping",
        classes = @ConstructorResult(
                targetClass = RoleDtoResponse.class,
                columns = {
                        @ColumnResult(name = "role_id", type = Integer.class),
                        @ColumnResult(name = "role_name", type = String.class),
                        @ColumnResult(name = "description", type = String.class),
                        @ColumnResult(name = "count", type = Integer.class)
                }
        )
)
@NamedNativeQuery(
        name = "GetRoleDtoResponse",
        query = "SELECT roles.role_id AS role_id, roles.role_name AS role_name, " +
                "roles.description AS description, COUNT(users_roles.user_id) AS count " +
                "FROM users_roles " +
                "INNER JOIN roles ON users_roles.role_id = roles.role_id " +
                "WHERE users_roles.role_id = :role_id " +
                "GROUP BY roles.role_id, roles.role_name, roles.description",
        resultSetMapping = "RoleDtoResponseMapping"
)
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Integer roleId;

    String roleName;

    String description;

    @ManyToMany(mappedBy = "roles")
    Set<User> users;


}
