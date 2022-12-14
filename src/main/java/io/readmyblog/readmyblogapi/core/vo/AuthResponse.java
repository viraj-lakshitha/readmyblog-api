package io.readmyblog.readmyblogapi.core.vo;

import io.readmyblog.readmyblogapi.auth.AuthTokens;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    private String accessToken;

    private String refreshToken;

    private String tokenType = "Bearer";

    public AuthResponse(AuthTokens authTokens) {
        this.accessToken = authTokens.getAccessToken();
        this.refreshToken = authTokens.getRefreshToken();
    }

    public AuthResponse(String accessToken) {
        this.accessToken = accessToken;
    }

}
