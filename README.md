# athenz_user_cert

This is an unofficial repository to provide tools, packages and instructions for [Athenz](https://www.athenz.io).

It is currently owned and maintained by [ctyano](https://github.com/ctyano).

The `athenz_user_cert` interacts with an OAuth 2.0 Identity Provider to obtain an OAuth access token.  
It then communicates with the Certificate Signer API (e.g., [certsigner-envoy](https://github.com/ctyano/certsigner-envoy)) to retrieve an X.509 certificate.  
This certificate is compatible with Athenz and can be used to authenticate the user.  

## How it works

[![](https://img.plantuml.biz/plantuml/svg/ZLLDRzim3BthLn3kfSNW5RtkK7JjWA5OXns6Oi3QOP1bDjQgIAu-cYP3_lj8oKxjPbyvE8hrtYFvH2fd8KeVqz88WtSHeWEl5rs4LdjKKJihHDJH85HlOuTs0zS1uKBImrdua1hq5YE6IWYfelDJcAz01aYq4FHGpAc-O0Fdtgt6tQQidm43_UBgCkyhe_VsM1ekq4T6tTh3bVFtWS5EfjX1dngZ5JFHngDT3ee91v-yj0iKGXcNMgYU2o1y2f6p-Ya0bFJjBfv78oEsG6aah-CQb5lspf9wA6Z-58Row_vUbymz75onbUyzejtX0AnhSKJMmTt5BYmB8qnG03S5ygs8yNAwEH3pxh3URM_5_Fk6QmzwOT7NlNTFwttJ-E6ytaW-SghKFw8_okAPC0gr-BJFrIrPmRuGz95-34J2phmfRkPAPJ6s-7Dk4kxPKn1rAbwckJ7SHDUNEKZIUrM_aDWiGrtgoLARkTJNZv-p3g7-9TGsMQ1jPWgjZBAPTkUxyse6e20a_hsaS6j7_1YrRIROxM-FS2ksWeV0GrtNf-F8m1keN8-sccnHp_DhVCBS_t0CnYbfEXVYS5PbAgQStMnCY3JDOvGwzIz0pv9IAGm13hiO-wCfXndwhzYTuEjJRXJ6UYntpbXWDTCRG7yKv78PHvOoJlQQsiuOM6cgEbURmosZ6JY1vZh4QIfCpztE0ln6tsb5amyyEjhg1J4U4f56WLVmOyKA8irYUvJjyOfk2XoJLCv6xmpqZcwczK0d8XC68hKLKNVTD11pzeVBTNWm7ATabqywNmZ_cIZRK_1C7MuBvkxZ-tiLJauuriYuwNHB0_wDpw0HuWnjo_yMlm00)](https://editor.plantuml.com/uml/ZLLDRzim3BthLn3kfSNW5RtkK7JjWA5OXns6Oi3QOP1bDjQgIAu-cYP3_lj8oKxjPbyvE8hrtYFvH2fd8KeVqz88WtSHeWEl5rs4LdjKKJihHDJH85HlOuTs0zS1uKBImrdua1hq5YE6IWYfelDJcAz01aYq4FHGpAc-O0Fdtgt6tQQidm43_UBgCkyhe_VsM1ekq4T6tTh3bVFtWS5EfjX1dngZ5JFHngDT3ee91v-yj0iKGXcNMgYU2o1y2f6p-Ya0bFJjBfv78oEsG6aah-CQb5lspf9wA6Z-58Row_vUbymz75onbUyzejtX0AnhSKJMmTt5BYmB8qnG03S5ygs8yNAwEH3pxh3URM_5_Fk6QmzwOT7NlNTFwttJ-E6ytaW-SghKFw8_okAPC0gr-BJFrIrPmRuGz95-34J2phmfRkPAPJ6s-7Dk4kxPKn1rAbwckJ7SHDUNEKZIUrM_aDWiGrtgoLARkTJNZv-p3g7-9TGsMQ1jPWgjZBAPTkUxyse6e20a_hsaS6j7_1YrRIROxM-FS2ksWeV0GrtNf-F8m1keN8-sccnHp_DhVCBS_t0CnYbfEXVYS5PbAgQStMnCY3JDOvGwzIz0pv9IAGm13hiO-wCfXndwhzYTuEjJRXJ6UYntpbXWDTCRG7yKv78PHvOoJlQQsiuOM6cgEbURmosZ6JY1vZh4QIfCpztE0ln6tsb5amyyEjhg1J4U4f56WLVmOyKA8irYUvJjyOfk2XoJLCv6xmpqZcwczK0d8XC68hKLKNVTD11pzeVBTNWm7ATabqywNmZ_cIZRK_1C7MuBvkxZ-tiLJauuriYuwNHB0_wDpw0HuWnjo_yMlm00)

## How to install

```
brew tap ctyano/athenz_user_cert https://github.com/ctyano/athenz_user_cert
```

```
brew install ctyano/athenz_user_cert/athenz_user_cert
```

## List of Distributions

### Docker(OCI) Image

[athenz_user_cert](https://github.com/users/ctyano/packages/container/package/athenz_user_cert)

### Executable binaries

https://github.com/ctyano/athenz_user_cert/releases

## How to build

```
make
```

