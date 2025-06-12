package blockchain.didblockchainproject.repository;

import com.doeun.did.contract.CredentialRegistry;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.utils.Numeric;

@Repository
public class DidRepository {

    @Value("${contract.credential-registry-address}")
    private String contractAddress;

    private final Web3j web3j;
    private final Credentials credentials;
    private final ContractGasProvider gasProvider;

    public DidRepository(Web3j web3j, Credentials credentials, ContractGasProvider gasProvider) {
        this.web3j = web3j;
        this.credentials = credentials;
        this.gasProvider = gasProvider;
    }

    public void registerOnBlockchain(String hash, long validityInSec, int type) {
        try {
            CredentialRegistry contract = CredentialRegistry.loadWithoutEns(
                    contractAddress, web3j, credentials, gasProvider
            );

            System.out.println("잔고: " + web3j.ethGetBalance(credentials.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());

            // String -> byte[] 변환
            byte[] hashBytes = Numeric.hexStringToByteArray(hash);

            TransactionReceipt receipt = contract.registerCredential(
                    hashBytes,
                    BigInteger.valueOf(validityInSec),
                    BigInteger.valueOf(type)
            ).send();
        } catch (Exception e) {
            throw new RuntimeException("블록체인 등록 실패", e);
        }
    }

    public boolean verifyOnBlockchain(String issuer, String hash) {
        try {
            CredentialRegistry contract = CredentialRegistry.loadWithoutEns(
                    contractAddress, web3j, credentials, gasProvider
            );

            byte[] hashBytes = Numeric.hexStringToByteArray(hash);
            System.out.println("Issuer: " + issuer);  // 확인용 로그

            return contract.verifyCredential(issuer, hashBytes).send();
        } catch (Exception e) {
            throw new RuntimeException("검증 실패", e);
        }
    }

    public String generateQrCodeBase64(String data) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            BitMatrix matrix = new MultiFormatWriter().encode(data, BarcodeFormat.QR_CODE, 200, 200);
            MatrixToImageWriter.writeToStream(matrix, "PNG", out);
            return Base64.getEncoder().encodeToString(out.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("QR 생성 실패", e);
        }
    }
}


