package blockchain.didblockchainproject.config;

import java.math.BigInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.Web3jService;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.tx.gas.StaticGasProvider;
import org.web3j.utils.Async;
import org.web3j.utils.Convert;

@Configuration
public class Web3Config {

    @Value("${web3j.client-address}")
    private String clientAddress;

    @Value("${wallet.private-key}")
    private String privateKey;

    @Bean
    public Web3jService web3jService() {
        // 이 HttpService는 ENS 기능을 포함하지 않음
        return new HttpService(clientAddress);
    }

    @Bean
    public Web3j web3j(Web3jService web3jService) {
        // Web3jService로부터 직접 Web3j 생성
        return Web3j.build(web3jService, 2000, Async.defaultExecutorService());
    }

    @Bean
    public Credentials credentials() {
        return Credentials.create(privateKey);
    }

    @Bean
    public ContractGasProvider contractGasProvider() {
        return new StaticGasProvider(
                Convert.toWei("1", Convert.Unit.GWEI).toBigInteger(), // gasPrice
                BigInteger.valueOf(3_000_000)                         // gasLimit
        );
    }

}

