package io.readmyblog.readmyblogapi.core.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.readmyblog.readmyblogapi.core.AuthProvider;
import io.readmyblog.readmyblogapi.core.Role;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.validation.constraints.NotNull;
import java.util.Date;

@Document(collection = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class User {
    @Id
    private String id;
    @NotNull
    private String name;

    private String userName;

    @NotNull
    @Indexed(unique = true)
    private String email;

    private String imageUrl;

    @NotNull
    @Builder.Default
    private Boolean emailVerified = false;

    @JsonIgnore
    private String password;

    @NotNull
    private AuthProvider provider;

    private String providerId;

    private Role role;

    @Builder.Default
    private Boolean isActive = true;

    @CreatedDate
    private Date createdAt;
}
