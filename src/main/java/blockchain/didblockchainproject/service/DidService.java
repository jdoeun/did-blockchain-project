package blockchain.didblockchainproject.service;

import blockchain.didblockchainproject.dto.CredentialDto.CredentialRegisterRequest;
import blockchain.didblockchainproject.dto.CredentialDto.CredentialRegisterResponse;
import blockchain.didblockchainproject.dto.CredentialDto.CredentialVerifyRequest;
import blockchain.didblockchainproject.dto.CredentialDto.CredentialVerifyResponse;
import blockchain.didblockchainproject.repository.DidRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.Period;
import java.util.HashMap;
import java.util.Map;
import javax.imageio.ImageIO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

@Service
@RequiredArgsConstructor
public class DidService {

    private final DidRepository didRepository;

    @Value("${contract.credential-registry-address}")
    private String issuerAddress;

    public CredentialRegisterResponse registerCredential(CredentialRegisterRequest request) {
        // Credential 생성
        Map<String, Object> credential = new HashMap<>();
        credential.put("name", request.getName());
        credential.put("birth", request.getBirth());

        int year = Integer.parseInt(request.getBirth().substring(0, 4));
        boolean underAge = LocalDate.now().getYear() - year < 19;
        credential.put("underAge", underAge);

        String json;
        try {
            json = new ObjectMapper().writeValueAsString(credential);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("JSON 직렬화 실패", e);
        }

        byte[] hashBytes = Hash.sha3(json.getBytes(StandardCharsets.UTF_8));
        String hash = Numeric.toHexString(hashBytes);

        didRepository.registerOnBlockchain(hash, 31536000L, underAge ? 1 : 0);

        Map<String, Object> qrPayload = Map.of(
                "issuer", "0xe7Ba05e1F9509b1F0C2c547512EcBEee356532F9",
                "credentialHash", hash,
                "underAge", underAge
        );

        String qrJson;
        try {
            qrJson = new ObjectMapper().writeValueAsString(qrPayload);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("QR JSON 직렬화 실패", e);
        }

        String qrBase64 = didRepository.generateQrCodeBase64(qrJson);
        return new CredentialRegisterResponse(hash, qrBase64);
    }

    public CredentialVerifyResponse verifyCredentialFromQr(MultipartFile qrImage) {
        try {
            BufferedImage image = ImageIO.read(qrImage.getInputStream());
            LuminanceSource source = new BufferedImageLuminanceSource(image);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
            Result result = new MultiFormatReader().decode(bitmap);

            // QR 코드 안에는 JSON string이 있다고 가정
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> qrData = mapper.readValue(result.getText(), Map.class);

            String issuer = (String) qrData.get("issuer");
            String hash = (String) qrData.get("credentialHash");
            boolean underAge = Boolean.parseBoolean(qrData.get("underAge").toString());

            boolean valid = didRepository.verifyOnBlockchain(issuer, hash);

            return new CredentialVerifyResponse(valid, underAge);

        } catch (Exception e) {
            throw new RuntimeException("QR 검증 실패", e);
        }
    }



}
