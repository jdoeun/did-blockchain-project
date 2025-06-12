package com.doeun.did.contract;

import io.reactivex.Flowable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Bool;
import org.web3j.abi.datatypes.Event;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.RemoteFunctionCall;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.response.BaseEventResponse;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.gas.ContractGasProvider;
import org.web3j.utils.Numeric;

/**
 * <p>Auto generated code.
 * <p><strong>Do not modify!</strong>
 * <p>Please use the <a href="https://docs.web3j.io/command_line.html">web3j command line tools</a>,
 * or the org.web3j.codegen.SolidityFunctionWrapperGenerator in the 
 * <a href="https://github.com/LFDT-web3j/web3j/tree/main/codegen">codegen module</a> to update.
 *
 * <p>Generated with web3j version 1.7.0.
 */
@SuppressWarnings("rawtypes")
public class CredentialRegistry extends Contract {
    public static final String BINARY = "608060405234801561001057600080fd5b5061002d61002261003260201b60201c565b61003a60201b60201c565b6100fe565b600033905090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b611cbb8061010d6000396000f3fe608060405234801561001057600080fd5b50600436106100cf5760003560e01c80638da5cb5b1161008c578063d1663b4e11610066578063d1663b4e14610210578063d8f5e9ef1461022c578063f2fde38b14610248578063f33712a714610264576100cf565b80638da5cb5b146101a6578063965a3f94146101c4578063ca6eec78146101f4576100cf565b806318c6ed62146100d457806320694db01461010457806347bc7093146101205780635f889e171461013c578063715018a61461016c578063877b9a6714610176575b600080fd5b6100ee60048036038101906100e9919061130d565b610294565b6040516100fb9190611368565b60405180910390f35b61011e60048036038101906101199190611383565b610347565b005b61013a60048036038101906101359190611383565b6104ed565b005b6101566004803603810190610151919061130d565b610693565b6040516101639190611368565b60405180910390f35b610174610701565b005b610190600480360381019061018b9190611383565b610789565b60405161019d9190611368565b60405180910390f35b6101ae6107a9565b6040516101bb91906113bf565b60405180910390f35b6101de60048036038101906101d9919061130d565b6107d2565b6040516101eb9190611451565b60405180910390f35b61020e6004803603810190610209919061146c565b610801565b005b61022a600480360381019061022591906114f4565b6109c3565b005b61024660048036038101906102419190611547565b610cc6565b005b610262600480360381019061025d9190611383565b611049565b005b61027e6004803603810190610279919061130d565b611140565b60405161028b9190611451565b60405180910390f35b600080600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002054905060006001821180156102fb57508142105b90507fa99d489c9c1a4e33f87a554dcaa2bd2a6d8976b2eca7a08b6f8263082b49202433868684426040516103349594939291906115cc565b60405180910390a1809250505092915050565b61034f6111a8565b73ffffffffffffffffffffffffffffffffffffffff1661036d6107a9565b73ffffffffffffffffffffffffffffffffffffffff16146103c3576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103ba9061167c565b60405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff1615610450576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610447906116e8565b60405180910390fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055508073ffffffffffffffffffffffffffffffffffffffff167f05e7c881d716bee8cb7ed92293133ba156704252439e5c502c277448f04e20c260405160405180910390a250565b6104f56111a8565b73ffffffffffffffffffffffffffffffffffffffff166105136107a9565b73ffffffffffffffffffffffffffffffffffffffff1614610569576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105609061167c565b60405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff166105f5576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016105ec90611754565b60405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055508073ffffffffffffffffffffffffffffffffffffffff167faf66545c919a3be306ee446d8f42a9558b5b022620df880517bc9593ec0f2d5260405160405180910390a250565b600080600260008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008481526020019081526020016000205490506001811180156106f857508042105b91505092915050565b6107096111a8565b73ffffffffffffffffffffffffffffffffffffffff166107276107a9565b73ffffffffffffffffffffffffffffffffffffffff161461077d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107749061167c565b60405180910390fd5b61078760006111b0565b565b60016020528060005260406000206000915054906101000a900460ff1681565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60036020528160005260406000206020528060005260406000206000915091509054906101000a900460ff1681565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff1661088d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610884906117e6565b60405180910390fd5b6000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600083815260200190815260200160002054905060018111610925576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161091c90611878565b60405180910390fd5b6001600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600084815260200190815260200160002081905550813373ffffffffffffffffffffffffffffffffffffffff167f3026993f4e06fc52b2f2f8ee2035821b9b29172ab964da353b6ba3c89133727e60405160405180910390a35050565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16610a4f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a46906117e6565b60405180910390fd5b60008211610a92576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a89906118e4565b60405180910390fd5b60006003811115610aa657610aa56113da565b5b816003811115610ab957610ab86113da565b5b03610af9576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610af090611950565b60405180910390fd5b6000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600085815260200190815260200160002054905060008114610b91576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b88906119e2565b60405180910390fd5b60008342610b9f9190611a31565b905080600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008781526020019081526020016000208190555082600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600087815260200190815260200160002060006101000a81548160ff02191690836003811115610c6957610c686113da565b5b0217905550843373ffffffffffffffffffffffffffffffffffffffff167f8b6ff2eb35c0017adcb04d577c8f0c74f40d2209cd7710389759fe2483c58b208584604051610cb7929190611a87565b60405180910390a35050505050565b600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060009054906101000a900460ff16610d52576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d49906117e6565b60405180910390fd5b60008211610d95576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d8c906118e4565b60405180910390fd5b6001600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008681526020019081526020016000205411610e28576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610e1f90611b22565b60405180910390fd5b6000600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008581526020019081526020016000205414610ebb576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610eb290611b8e565b60405180910390fd5b6001600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008681526020019081526020016000208190555060008242610f1f9190611a31565b905080600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008681526020019081526020016000208190555081600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600086815260200190815260200160002060006101000a81548160ff02191690836003811115610fe957610fe86113da565b5b02179055503373ffffffffffffffffffffffffffffffffffffffff167f894817147d1b4aa5025577aa70e90e1f509a689ec7305e51dd13de054bde80ab8686858560405161103a9493929190611bae565b60405180910390a25050505050565b6110516111a8565b73ffffffffffffffffffffffffffffffffffffffff1661106f6107a9565b73ffffffffffffffffffffffffffffffffffffffff16146110c5576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016110bc9061167c565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603611134576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161112b90611c65565b60405180910390fd5b61113d816111b0565b50565b6000600360008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600083815260200190815260200160002060009054906101000a900460ff16905092915050565b600033905090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050816000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006112a482611279565b9050919050565b6112b481611299565b81146112bf57600080fd5b50565b6000813590506112d1816112ab565b92915050565b6000819050919050565b6112ea816112d7565b81146112f557600080fd5b50565b600081359050611307816112e1565b92915050565b6000806040838503121561132457611323611274565b5b6000611332858286016112c2565b9250506020611343858286016112f8565b9150509250929050565b60008115159050919050565b6113628161134d565b82525050565b600060208201905061137d6000830184611359565b92915050565b60006020828403121561139957611398611274565b5b60006113a7848285016112c2565b91505092915050565b6113b981611299565b82525050565b60006020820190506113d460008301846113b0565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602160045260246000fd5b6004811061141a576114196113da565b5b50565b600081905061142b82611409565b919050565b600061143b8261141d565b9050919050565b61144b81611430565b82525050565b60006020820190506114666000830184611442565b92915050565b60006020828403121561148257611481611274565b5b6000611490848285016112f8565b91505092915050565b6000819050919050565b6114ac81611499565b81146114b757600080fd5b50565b6000813590506114c9816114a3565b92915050565b600481106114dc57600080fd5b50565b6000813590506114ee816114cf565b92915050565b60008060006060848603121561150d5761150c611274565b5b600061151b868287016112f8565b935050602061152c868287016114ba565b925050604061153d868287016114df565b9150509250925092565b6000806000806080858703121561156157611560611274565b5b600061156f878288016112f8565b9450506020611580878288016112f8565b9350506040611591878288016114ba565b92505060606115a2878288016114df565b91505092959194509250565b6115b7816112d7565b82525050565b6115c681611499565b82525050565b600060a0820190506115e160008301886113b0565b6115ee60208301876113b0565b6115fb60408301866115ae565b6116086060830185611359565b61161560808301846115bd565b9695505050505050565b600082825260208201905092915050565b7f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572600082015250565b600061166660208361161f565b915061167182611630565b602082019050919050565b6000602082019050818103600083015261169581611659565b9050919050565b7f49737375657220616c7265616479207265676973746572656400000000000000600082015250565b60006116d260198361161f565b91506116dd8261169c565b602082019050919050565b60006020820190508181036000830152611701816116c5565b9050919050565b7f497373756572206e6f7420666f756e6400000000000000000000000000000000600082015250565b600061173e60108361161f565b915061174982611708565b602082019050919050565b6000602082019050818103600083015261176d81611731565b9050919050565b7f43616c6c6572206973206e6f742061207265676973746572656420697373756560008201527f7200000000000000000000000000000000000000000000000000000000000000602082015250565b60006117d060218361161f565b91506117db82611774565b604082019050919050565b600060208201905081810360008301526117ff816117c3565b9050919050565b7f43726564656e7469616c206e6f7420666f756e64206f7220616c72656164792060008201527f7265766f6b656400000000000000000000000000000000000000000000000000602082015250565b600061186260278361161f565b915061186d82611806565b604082019050919050565b6000602082019050818103600083015261189181611855565b9050919050565b7f56616c6964697479206d7573742062652067726561746572207468616e203000600082015250565b60006118ce601f8361161f565b91506118d982611898565b602082019050919050565b600060208201905081810360008301526118fd816118c1565b9050919050565b7f496e76616c69642063726564656e7469616c2074797065000000000000000000600082015250565b600061193a60178361161f565b915061194582611904565b602082019050919050565b600060208201905081810360008301526119698161192d565b9050919050565b7f43726564656e7469616c20616c726561647920657869737473206f722077617360008201527f207265766f6b6564000000000000000000000000000000000000000000000000602082015250565b60006119cc60288361161f565b91506119d782611970565b604082019050919050565b600060208201905081810360008301526119fb816119bf565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000611a3c82611499565b9150611a4783611499565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115611a7c57611a7b611a02565b5b828201905092915050565b6000604082019050611a9c6000830185611442565b611aa960208301846115bd565b9392505050565b7f4f6c642063726564656e7469616c206e6f7420666f756e64206f7220616c726560008201527f616479207265766f6b6564000000000000000000000000000000000000000000602082015250565b6000611b0c602b8361161f565b9150611b1782611ab0565b604082019050919050565b60006020820190508181036000830152611b3b81611aff565b9050919050565b7f4e65772063726564656e7469616c20616c726561647920657869737473000000600082015250565b6000611b78601d8361161f565b9150611b8382611b42565b602082019050919050565b60006020820190508181036000830152611ba781611b6b565b9050919050565b6000608082019050611bc360008301876115ae565b611bd060208301866115ae565b611bdd6040830185611442565b611bea60608301846115bd565b95945050505050565b7f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160008201527f6464726573730000000000000000000000000000000000000000000000000000602082015250565b6000611c4f60268361161f565b9150611c5a82611bf3565b604082019050919050565b60006020820190508181036000830152611c7e81611c42565b905091905056fea2646970667358221220ecdc296cc05eb810737c5d69a17cdfce786a2aaea74cab1dad4f011dbd20a94064736f6c634300080d0033";

    private static String librariesLinkedBinary;

    public static final String FUNC_ADDISSUER = "addIssuer";

    public static final String FUNC_REGISTERCREDENTIAL = "registerCredential";

    public static final String FUNC_REMOVEISSUER = "removeIssuer";

    public static final String FUNC_RENOUNCEOWNERSHIP = "renounceOwnership";

    public static final String FUNC_REVOKECREDENTIAL = "revokeCredential";

    public static final String FUNC_TRANSFEROWNERSHIP = "transferOwnership";

    public static final String FUNC_UPDATECREDENTIAL = "updateCredential";

    public static final String FUNC_VERIFYANDLOG = "verifyAndLog";

    public static final String FUNC_CREDENTIALTYPES = "credentialTypes";

    public static final String FUNC_GETCREDENTIALTYPE = "getCredentialType";

    public static final String FUNC_ISISSUER = "isIssuer";

    public static final String FUNC_OWNER = "owner";

    public static final String FUNC_VERIFYCREDENTIAL = "verifyCredential";

    public static final Event CREDENTIALREGISTERED_EVENT = new Event("CredentialRegistered", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>(true) {}, new TypeReference<Bytes32>(true) {}, new TypeReference<Uint8>() {}, new TypeReference<Uint256>() {}));
    ;

    public static final Event CREDENTIALREVOKED_EVENT = new Event("CredentialRevoked", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>(true) {}, new TypeReference<Bytes32>(true) {}));
    ;

    public static final Event CREDENTIALUPDATED_EVENT = new Event("CredentialUpdated", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>(true) {}, new TypeReference<Bytes32>() {}, new TypeReference<Bytes32>() {}, new TypeReference<Uint8>() {}, new TypeReference<Uint256>() {}));
    ;

    public static final Event CREDENTIALVERIFIED_EVENT = new Event("CredentialVerified", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>() {}, new TypeReference<Address>() {}, new TypeReference<Bytes32>() {}, new TypeReference<Bool>() {}, new TypeReference<Uint256>() {}));
    ;

    public static final Event ISSUERADDED_EVENT = new Event("IssuerAdded", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>(true) {}));
    ;

    public static final Event ISSUERREMOVED_EVENT = new Event("IssuerRemoved", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>(true) {}));
    ;

    public static final Event OWNERSHIPTRANSFERRED_EVENT = new Event("OwnershipTransferred", 
            Arrays.<TypeReference<?>>asList(new TypeReference<Address>(true) {}, new TypeReference<Address>(true) {}));
    ;

    @Deprecated
    protected CredentialRegistry(String contractAddress, Web3j web3j, Credentials credentials,
            BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    protected CredentialRegistry(String contractAddress, Web3j web3j, Credentials credentials,
            ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, credentials, contractGasProvider);
    }

    @Deprecated
    protected CredentialRegistry(String contractAddress, Web3j web3j,
            TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    protected CredentialRegistry(String contractAddress, Web3j web3j,
            TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        super(BINARY, contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public RemoteFunctionCall<TransactionReceipt> addIssuer(String _issuerAddress) {
        final Function function = new Function(
                FUNC_ADDISSUER, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, _issuerAddress)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public static List<CredentialRegisteredEventResponse> getCredentialRegisteredEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(CREDENTIALREGISTERED_EVENT, transactionReceipt);
        ArrayList<CredentialRegisteredEventResponse> responses = new ArrayList<CredentialRegisteredEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            CredentialRegisteredEventResponse typedResponse = new CredentialRegisteredEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
            typedResponse.credentialHash = (byte[]) eventValues.getIndexedValues().get(1).getValue();
            typedResponse.ctype = (BigInteger) eventValues.getNonIndexedValues().get(0).getValue();
            typedResponse.expiresAt = (BigInteger) eventValues.getNonIndexedValues().get(1).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static CredentialRegisteredEventResponse getCredentialRegisteredEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(CREDENTIALREGISTERED_EVENT, log);
        CredentialRegisteredEventResponse typedResponse = new CredentialRegisteredEventResponse();
        typedResponse.log = log;
        typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
        typedResponse.credentialHash = (byte[]) eventValues.getIndexedValues().get(1).getValue();
        typedResponse.ctype = (BigInteger) eventValues.getNonIndexedValues().get(0).getValue();
        typedResponse.expiresAt = (BigInteger) eventValues.getNonIndexedValues().get(1).getValue();
        return typedResponse;
    }

    public Flowable<CredentialRegisteredEventResponse> credentialRegisteredEventFlowable(
            EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getCredentialRegisteredEventFromLog(log));
    }

    public Flowable<CredentialRegisteredEventResponse> credentialRegisteredEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(CREDENTIALREGISTERED_EVENT));
        return credentialRegisteredEventFlowable(filter);
    }

    public static List<CredentialRevokedEventResponse> getCredentialRevokedEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(CREDENTIALREVOKED_EVENT, transactionReceipt);
        ArrayList<CredentialRevokedEventResponse> responses = new ArrayList<CredentialRevokedEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            CredentialRevokedEventResponse typedResponse = new CredentialRevokedEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
            typedResponse.credentialHash = (byte[]) eventValues.getIndexedValues().get(1).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static CredentialRevokedEventResponse getCredentialRevokedEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(CREDENTIALREVOKED_EVENT, log);
        CredentialRevokedEventResponse typedResponse = new CredentialRevokedEventResponse();
        typedResponse.log = log;
        typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
        typedResponse.credentialHash = (byte[]) eventValues.getIndexedValues().get(1).getValue();
        return typedResponse;
    }

    public Flowable<CredentialRevokedEventResponse> credentialRevokedEventFlowable(
            EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getCredentialRevokedEventFromLog(log));
    }

    public Flowable<CredentialRevokedEventResponse> credentialRevokedEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(CREDENTIALREVOKED_EVENT));
        return credentialRevokedEventFlowable(filter);
    }

    public static List<CredentialUpdatedEventResponse> getCredentialUpdatedEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(CREDENTIALUPDATED_EVENT, transactionReceipt);
        ArrayList<CredentialUpdatedEventResponse> responses = new ArrayList<CredentialUpdatedEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            CredentialUpdatedEventResponse typedResponse = new CredentialUpdatedEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
            typedResponse.oldHash = (byte[]) eventValues.getNonIndexedValues().get(0).getValue();
            typedResponse.newHash = (byte[]) eventValues.getNonIndexedValues().get(1).getValue();
            typedResponse.newType = (BigInteger) eventValues.getNonIndexedValues().get(2).getValue();
            typedResponse.newExpiresAt = (BigInteger) eventValues.getNonIndexedValues().get(3).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static CredentialUpdatedEventResponse getCredentialUpdatedEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(CREDENTIALUPDATED_EVENT, log);
        CredentialUpdatedEventResponse typedResponse = new CredentialUpdatedEventResponse();
        typedResponse.log = log;
        typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
        typedResponse.oldHash = (byte[]) eventValues.getNonIndexedValues().get(0).getValue();
        typedResponse.newHash = (byte[]) eventValues.getNonIndexedValues().get(1).getValue();
        typedResponse.newType = (BigInteger) eventValues.getNonIndexedValues().get(2).getValue();
        typedResponse.newExpiresAt = (BigInteger) eventValues.getNonIndexedValues().get(3).getValue();
        return typedResponse;
    }

    public Flowable<CredentialUpdatedEventResponse> credentialUpdatedEventFlowable(
            EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getCredentialUpdatedEventFromLog(log));
    }

    public Flowable<CredentialUpdatedEventResponse> credentialUpdatedEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(CREDENTIALUPDATED_EVENT));
        return credentialUpdatedEventFlowable(filter);
    }

    public static List<CredentialVerifiedEventResponse> getCredentialVerifiedEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(CREDENTIALVERIFIED_EVENT, transactionReceipt);
        ArrayList<CredentialVerifiedEventResponse> responses = new ArrayList<CredentialVerifiedEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            CredentialVerifiedEventResponse typedResponse = new CredentialVerifiedEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.verifier = (String) eventValues.getNonIndexedValues().get(0).getValue();
            typedResponse.issuer = (String) eventValues.getNonIndexedValues().get(1).getValue();
            typedResponse.credentialHash = (byte[]) eventValues.getNonIndexedValues().get(2).getValue();
            typedResponse.valid = (Boolean) eventValues.getNonIndexedValues().get(3).getValue();
            typedResponse.timestamp = (BigInteger) eventValues.getNonIndexedValues().get(4).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static CredentialVerifiedEventResponse getCredentialVerifiedEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(CREDENTIALVERIFIED_EVENT, log);
        CredentialVerifiedEventResponse typedResponse = new CredentialVerifiedEventResponse();
        typedResponse.log = log;
        typedResponse.verifier = (String) eventValues.getNonIndexedValues().get(0).getValue();
        typedResponse.issuer = (String) eventValues.getNonIndexedValues().get(1).getValue();
        typedResponse.credentialHash = (byte[]) eventValues.getNonIndexedValues().get(2).getValue();
        typedResponse.valid = (Boolean) eventValues.getNonIndexedValues().get(3).getValue();
        typedResponse.timestamp = (BigInteger) eventValues.getNonIndexedValues().get(4).getValue();
        return typedResponse;
    }

    public Flowable<CredentialVerifiedEventResponse> credentialVerifiedEventFlowable(
            EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getCredentialVerifiedEventFromLog(log));
    }

    public Flowable<CredentialVerifiedEventResponse> credentialVerifiedEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(CREDENTIALVERIFIED_EVENT));
        return credentialVerifiedEventFlowable(filter);
    }

    public static List<IssuerAddedEventResponse> getIssuerAddedEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(ISSUERADDED_EVENT, transactionReceipt);
        ArrayList<IssuerAddedEventResponse> responses = new ArrayList<IssuerAddedEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            IssuerAddedEventResponse typedResponse = new IssuerAddedEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static IssuerAddedEventResponse getIssuerAddedEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(ISSUERADDED_EVENT, log);
        IssuerAddedEventResponse typedResponse = new IssuerAddedEventResponse();
        typedResponse.log = log;
        typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
        return typedResponse;
    }

    public Flowable<IssuerAddedEventResponse> issuerAddedEventFlowable(EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getIssuerAddedEventFromLog(log));
    }

    public Flowable<IssuerAddedEventResponse> issuerAddedEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(ISSUERADDED_EVENT));
        return issuerAddedEventFlowable(filter);
    }

    public static List<IssuerRemovedEventResponse> getIssuerRemovedEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(ISSUERREMOVED_EVENT, transactionReceipt);
        ArrayList<IssuerRemovedEventResponse> responses = new ArrayList<IssuerRemovedEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            IssuerRemovedEventResponse typedResponse = new IssuerRemovedEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static IssuerRemovedEventResponse getIssuerRemovedEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(ISSUERREMOVED_EVENT, log);
        IssuerRemovedEventResponse typedResponse = new IssuerRemovedEventResponse();
        typedResponse.log = log;
        typedResponse.issuer = (String) eventValues.getIndexedValues().get(0).getValue();
        return typedResponse;
    }

    public Flowable<IssuerRemovedEventResponse> issuerRemovedEventFlowable(EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getIssuerRemovedEventFromLog(log));
    }

    public Flowable<IssuerRemovedEventResponse> issuerRemovedEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(ISSUERREMOVED_EVENT));
        return issuerRemovedEventFlowable(filter);
    }

    public static List<OwnershipTransferredEventResponse> getOwnershipTransferredEvents(
            TransactionReceipt transactionReceipt) {
        List<Contract.EventValuesWithLog> valueList = staticExtractEventParametersWithLog(OWNERSHIPTRANSFERRED_EVENT, transactionReceipt);
        ArrayList<OwnershipTransferredEventResponse> responses = new ArrayList<OwnershipTransferredEventResponse>(valueList.size());
        for (Contract.EventValuesWithLog eventValues : valueList) {
            OwnershipTransferredEventResponse typedResponse = new OwnershipTransferredEventResponse();
            typedResponse.log = eventValues.getLog();
            typedResponse.previousOwner = (String) eventValues.getIndexedValues().get(0).getValue();
            typedResponse.newOwner = (String) eventValues.getIndexedValues().get(1).getValue();
            responses.add(typedResponse);
        }
        return responses;
    }

    public static OwnershipTransferredEventResponse getOwnershipTransferredEventFromLog(Log log) {
        Contract.EventValuesWithLog eventValues = staticExtractEventParametersWithLog(OWNERSHIPTRANSFERRED_EVENT, log);
        OwnershipTransferredEventResponse typedResponse = new OwnershipTransferredEventResponse();
        typedResponse.log = log;
        typedResponse.previousOwner = (String) eventValues.getIndexedValues().get(0).getValue();
        typedResponse.newOwner = (String) eventValues.getIndexedValues().get(1).getValue();
        return typedResponse;
    }

    public Flowable<OwnershipTransferredEventResponse> ownershipTransferredEventFlowable(
            EthFilter filter) {
        return web3j.ethLogFlowable(filter).map(log -> getOwnershipTransferredEventFromLog(log));
    }

    public Flowable<OwnershipTransferredEventResponse> ownershipTransferredEventFlowable(
            DefaultBlockParameter startBlock, DefaultBlockParameter endBlock) {
        EthFilter filter = new EthFilter(startBlock, endBlock, getContractAddress());
        filter.addSingleTopic(EventEncoder.encode(OWNERSHIPTRANSFERRED_EVENT));
        return ownershipTransferredEventFlowable(filter);
    }

    public RemoteFunctionCall<TransactionReceipt> registerCredential(byte[] _credentialHash,
            BigInteger _validityInSeconds, BigInteger _type) {
        final Function function = new Function(
                FUNC_REGISTERCREDENTIAL, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.generated.Bytes32(_credentialHash), 
                new org.web3j.abi.datatypes.generated.Uint256(_validityInSeconds), 
                new org.web3j.abi.datatypes.generated.Uint8(_type)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> removeIssuer(String _issuerAddress) {
        final Function function = new Function(
                FUNC_REMOVEISSUER, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, _issuerAddress)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> renounceOwnership() {
        final Function function = new Function(
                FUNC_RENOUNCEOWNERSHIP, 
                Arrays.<Type>asList(), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> revokeCredential(byte[] _credentialHash) {
        final Function function = new Function(
                FUNC_REVOKECREDENTIAL, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.generated.Bytes32(_credentialHash)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> transferOwnership(String newOwner) {
        final Function function = new Function(
                FUNC_TRANSFEROWNERSHIP, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, newOwner)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> updateCredential(byte[] _oldHash, byte[] _newHash,
            BigInteger _validityInSeconds, BigInteger _newType) {
        final Function function = new Function(
                FUNC_UPDATECREDENTIAL, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.generated.Bytes32(_oldHash), 
                new org.web3j.abi.datatypes.generated.Bytes32(_newHash), 
                new org.web3j.abi.datatypes.generated.Uint256(_validityInSeconds), 
                new org.web3j.abi.datatypes.generated.Uint8(_newType)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<TransactionReceipt> verifyAndLog(String _issuer,
            byte[] _credentialHash) {
        final Function function = new Function(
                FUNC_VERIFYANDLOG, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, _issuer), 
                new org.web3j.abi.datatypes.generated.Bytes32(_credentialHash)), 
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteFunctionCall<BigInteger> credentialTypes(String param0, byte[] param1) {
        final Function function = new Function(FUNC_CREDENTIALTYPES, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, param0), 
                new org.web3j.abi.datatypes.generated.Bytes32(param1)), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint8>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteFunctionCall<BigInteger> getCredentialType(String _issuer,
            byte[] _credentialHash) {
        final Function function = new Function(FUNC_GETCREDENTIALTYPE, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, _issuer), 
                new org.web3j.abi.datatypes.generated.Bytes32(_credentialHash)), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint8>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public RemoteFunctionCall<Boolean> isIssuer(String param0) {
        final Function function = new Function(FUNC_ISISSUER, 
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Address(160, param0)), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Bool>() {}));
        return executeRemoteCallSingleValueReturn(function, Boolean.class);
    }

    public RemoteFunctionCall<String> owner() {
        final Function function = new Function(FUNC_OWNER, 
                Arrays.<Type>asList(), 
                Arrays.<TypeReference<?>>asList(new TypeReference<Address>() {}));
        return executeRemoteCallSingleValueReturn(function, String.class);
    }

    public RemoteFunctionCall<Boolean> verifyCredential(String _issuer, byte[] _credentialHash) {
        final Address issuerAddress = new Address(_issuer);
        final Bytes32 hashParam = new Bytes32(_credentialHash);

        System.out.println("🧾 Function Name: " + FUNC_VERIFYCREDENTIAL);
        System.out.println("📬 Issuer (raw): " + _issuer);
        System.out.println("📬 Issuer (web3j): " + issuerAddress.toString());
        System.out.println("📦 CredentialHash: " + Numeric.toHexString(_credentialHash));
        System.out.println("📦 CredentialHash length: " + _credentialHash.length);

        final Function function = new Function(
                FUNC_VERIFYCREDENTIAL,
                Arrays.<Type>asList(issuerAddress, hashParam),
                Arrays.<TypeReference<?>>asList(new TypeReference<Bool>() {})
        );


        return executeRemoteCallSingleValueReturn(function, Boolean.class);
    }


    @Deprecated
    public static CredentialRegistry load(String contractAddress, Web3j web3j,
            Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return new CredentialRegistry(contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    @Deprecated
    public static CredentialRegistry load(String contractAddress, Web3j web3j,
            TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return new CredentialRegistry(contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    public static CredentialRegistry load(String contractAddress, Web3j web3j,
            Credentials credentials, ContractGasProvider contractGasProvider) {
        return new CredentialRegistry(contractAddress, web3j, credentials, contractGasProvider);
    }

    public static CredentialRegistry load(String contractAddress, Web3j web3j,
            TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        return new CredentialRegistry(contractAddress, web3j, transactionManager, contractGasProvider);
    }

    public static RemoteCall<CredentialRegistry> deploy(Web3j web3j, Credentials credentials,
            ContractGasProvider contractGasProvider) {
        return deployRemoteCall(CredentialRegistry.class, web3j, credentials, contractGasProvider, getDeploymentBinary(), "");
    }

    public static RemoteCall<CredentialRegistry> deploy(Web3j web3j,
            TransactionManager transactionManager, ContractGasProvider contractGasProvider) {
        return deployRemoteCall(CredentialRegistry.class, web3j, transactionManager, contractGasProvider, getDeploymentBinary(), "");
    }

    @Deprecated
    public static RemoteCall<CredentialRegistry> deploy(Web3j web3j, Credentials credentials,
            BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(CredentialRegistry.class, web3j, credentials, gasPrice, gasLimit, getDeploymentBinary(), "");
    }

    @Deprecated
    public static RemoteCall<CredentialRegistry> deploy(Web3j web3j,
            TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(CredentialRegistry.class, web3j, transactionManager, gasPrice, gasLimit, getDeploymentBinary(), "");
    }

//    public static void linkLibraries(List<Contract.LinkReference> references) {
//        librariesLinkedBinary = linkBinaryWithReferences(BINARY, references);
//    }

    private static String getDeploymentBinary() {
        if (librariesLinkedBinary != null) {
            return librariesLinkedBinary;
        } else {
            return BINARY;
        }
    }

    public static class CredentialRegisteredEventResponse extends BaseEventResponse {
        public String issuer;

        public byte[] credentialHash;

        public BigInteger ctype;

        public BigInteger expiresAt;
    }

    public static class CredentialRevokedEventResponse extends BaseEventResponse {
        public String issuer;

        public byte[] credentialHash;
    }

    public static class CredentialUpdatedEventResponse extends BaseEventResponse {
        public String issuer;

        public byte[] oldHash;

        public byte[] newHash;

        public BigInteger newType;

        public BigInteger newExpiresAt;
    }

    public static class CredentialVerifiedEventResponse extends BaseEventResponse {
        public String verifier;

        public String issuer;

        public byte[] credentialHash;

        public Boolean valid;

        public BigInteger timestamp;
    }

    public static class IssuerAddedEventResponse extends BaseEventResponse {
        public String issuer;
    }

    public static class IssuerRemovedEventResponse extends BaseEventResponse {
        public String issuer;
    }

    public static class OwnershipTransferredEventResponse extends BaseEventResponse {
        public String previousOwner;

        public String newOwner;
    }

    public static CredentialRegistry loadWithoutEns(
            String contractAddress,
            Web3j web3j,
            Credentials credentials,
            ContractGasProvider contractGasProvider
    ) {
        return new CredentialRegistry(contractAddress, web3j, credentials, contractGasProvider) {
            @Override
            protected String resolveContractAddress(String contractIdentifier) {
                // ENS 우회: 주소 그대로 반환
                return contractIdentifier;
            }
        };
    }
}
