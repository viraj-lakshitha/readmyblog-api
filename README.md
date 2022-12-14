# readmyblog.io

---
### Curl request to create account using APIs

```shell
curl --location --request POST 'http://localhost:8080/api/auth/signup' \
--header 'Content-Type: application/json' \
--data-raw '{
    "name": "User1",
    "email": "user1@readmyblog.io",
    "password": "User@123"
}'
```

### Tryout Google Authentication

Run project and navigate to this URL in your browser `http://localhost:8080/api/oauth2/authorize/google?redirect_uri`