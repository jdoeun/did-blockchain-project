package blockchain.didblockchainproject.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

public class CredentialDto {

    @Getter
    @AllArgsConstructor
    public static class CredentialRegisterRequest {
        private String name;
        private String birth;
    }

    @Getter
    @AllArgsConstructor
    public static class CredentialRegisterResponse {

        private String credentialHash;
        private String qrImageBase64;
    }

    @Getter
    @AllArgsConstructor
    public static class CredentialVerifyRequest {

        private String issuer; // 발급자 지갑 주소
        private String credentialHash;
        private boolean underAge;
    }

    @Getter
    @AllArgsConstructor
    public static class CredentialVerifyResponse {

        private boolean valid;
        private boolean underAge;
    }

}
