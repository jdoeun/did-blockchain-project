package blockchain.didblockchainproject.api;

import blockchain.didblockchainproject.dto.CredentialDto.CredentialRegisterRequest;
import blockchain.didblockchainproject.dto.CredentialDto.CredentialRegisterResponse;
import blockchain.didblockchainproject.dto.CredentialDto.CredentialVerifyRequest;
import blockchain.didblockchainproject.dto.CredentialDto.CredentialVerifyResponse;
import blockchain.didblockchainproject.service.DidService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/did")
@RequiredArgsConstructor
public class DidController {

    private final DidService didService;

    @PostMapping("/register")
    public ResponseEntity<CredentialRegisterResponse> registerCredential(
            @RequestBody CredentialRegisterRequest request
    ) {
        return ResponseEntity.ok(didService.registerCredential(request));
    }

    @PostMapping(value = "/verify-by-qr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<CredentialVerifyResponse> verifyCredentialFromQr(
            @RequestPart("file") MultipartFile qrImage
    ) {
        return ResponseEntity.ok(didService.verifyCredentialFromQr(qrImage));
    }
}
