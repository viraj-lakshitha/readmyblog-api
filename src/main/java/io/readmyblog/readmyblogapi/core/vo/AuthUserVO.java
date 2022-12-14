package io.readmyblog.readmyblogapi.core.vo;

import io.readmyblog.readmyblogapi.core.AuthProvider;
import io.readmyblog.readmyblogapi.core.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthUserVO {
    private String id;
    private String name;
    private String userName;
    private String email;
    private String imageUrl;
    private AuthProvider provider;
    private Role role;
    private boolean isActive;
}
