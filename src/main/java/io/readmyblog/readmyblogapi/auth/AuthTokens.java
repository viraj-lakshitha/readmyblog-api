package io.readmyblog.readmyblogapi.auth;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthTokens {

    private String accessToken;

    private String refreshToken;

}
