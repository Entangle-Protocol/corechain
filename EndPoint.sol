//SPDX-License-Identifier: BSL 1.1
pragma solidity ^0.8.19;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "./IProposer.sol";
import "./lib/OperationLib.sol";
import "./lib/PhotonFunctionSelectorLib.sol";
import "./lib/PhotonOperationMetaLib.sol";

/// @notice EndPoint contract
/// @dev Contract entry point for operation executing by executor to destination protocol
/// @dev Also contract contain photon-gov logic for adding and verify new protocols and transmitters
contract EndPoint is
    IProposer,
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    OwnableUpgradeable
{
    error Endpoint__InvalidProtocolId(bytes32);
    error Endpoint__ExecutorIsNotAllowed(bytes32, address, address);
    error Endpoint__ExecutorIsAlreadyAllowed(bytes32, address);
    error Endpoint__ProtocolIsNotAllowed(bytes32, address);
    error Endpoint__ProtocolIsNotAdded(bytes32);
    error Endpoint__OpIsNotApproved(uint256);
    error Endpoint__OpIsAlreadyExecuted(uint256); //0x6475bb6b
    error Endpoint__OpIsNotForThisChain(uint256);
    error Endpoint__IsNotAllowedProposer(address);
    error Endpoint__ZeroTransmittersCount(bytes32);
    error Endpoint__AddrTooBig(bytes32);
    error Endpoint__SelectorTooBig(bytes32);
    error Endpoint__ParamsTooBig(bytes32);
    error Endpoint__TryingToRemoveLastGovExecutor();
    error Endpoint__TargetCallError(bytes);
    error Endpoint__GovAlreadyInited();

    event AddAllowedProtocol(bytes32 indexed protocolId, uint256 consensusTargetRate, address[] transmitters);
    event AddAllowedProtocolAddress(bytes32 indexed protocolId, address protocolAddress);
    event RemoveAllowedProtocolAddress(bytes32 indexed protocolId, address protocolAddress);
    event AddAllowedProposerAddress(bytes32 indexed protocolId, address proposer);
    event RemoveAllowedProposer(bytes32 indexed protocolId, address proposer);
    event AddTransmitter(bytes32 indexed protocolId, address transmitter);
    event RemoveTransmitter(bytes32 indexed protocolId, address transmitter);
    event AddExecutor(bytes32 indexed protocolId, address executor);
    event RemoveExecutor(bytes32 indexed protocolId, address executor);
    event SetConsensusTargetRate(bytes32 indexed protocolId, uint256 rate);

    event ProposalExecuted(uint256 opHash, bool success, bytes ret);
    event Propose(
        bytes32 indexed protocolId,
        uint256 meta,
        uint256 nonce,
        uint256 indexed destChainId,
        bytes protocolAddress,
        bytes functionSelector,
        bytes params,
        bytes reserved
    );

    bytes32 public constant ADMIN = keccak256("ADMIN");
    bytes32 public constant GOV = keccak256("GOV");
    bytes32 public constant govProtocolId = bytes32("photon-gov");

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    /// @notice protocol info struct
    struct AllowedProtocolInfo {
        bool isCreated;
        uint256 consensusTargetRate; // percentage of proofs div numberOfAllowedTransmitters which should be reached to approve operation. Scaled with 10000 decimals, e.g. 6000 is 60%
    }
    mapping(bytes32 protocolId => uint256) public numberOfAllowedTransmitters;
    mapping(bytes32 proocolId => mapping(address => bool)) public allowedTransmitters;
    mapping(bytes32 proocolId => mapping(address => bool)) public executors;
    mapping(bytes32 proocolId => mapping(address => bool)) public allowedProposers;

    /// @notice protocol info map
    mapping(bytes32 protocolId => AllowedProtocolInfo) public allowedProtocolInfo;
    /// @notice map of protocol contract address to protocol id
    mapping(address protocolAddress => bytes32 protocolId) public protocolAddressToProtocolId;

    /// @notice map of executed operations
    mapping(uint256 opId => bool) public opExecutedMap;

    /// @notice 10000 = 100%
    uint256 constant rateDecimals = 10000;

    bytes masterSmartContract;
    uint256 eobChainId;
    uint256 globalNonce;
    mapping(bytes32 protocolId => uint256 protocolNonce) protocolNonce;
    uint govExecutorsCount;

    /** END of VARS **/

    function _isAllowedExecutorInternal(bytes calldata _protocolAddr) internal view {
        address protocolAddress = abi.decode(_protocolAddr, (address));
        bytes32 protocolId = protocolAddressToProtocolId[protocolAddress];
        if (!allowedProtocolInfo[protocolId].isCreated) {
            revert Endpoint__ProtocolIsNotAdded(protocolId);
        }
        if (!executors[protocolId][_msgSender()]) {
            revert Endpoint__ExecutorIsNotAllowed(protocolId, protocolAddress, _msgSender());
        }
    }

    modifier isAllowedExecutor(bytes calldata _protocolAddr) {
        _isAllowedExecutorInternal(_protocolAddr);
        _;
    }

    function _isAllowedProposerInternal(bytes32 protocolId) internal view {
        if (!allowedProposers[protocolId][_msgSender()]) {
            revert Endpoint__IsNotAllowedProposer(_msgSender());
        }
    }

    modifier isAllowedProposer(bytes32 protocolId) {
        _isAllowedProposerInternal(protocolId);
        _;
    }

    function _isValidProtocol(bytes32 _protocolId) internal view {
        if (_protocolId == bytes32(0)) revert Endpoint__InvalidProtocolId(_protocolId);
        if (!allowedProtocolInfo[_protocolId].isCreated)
            revert Endpoint__ProtocolIsNotAdded(_protocolId);
    }

    modifier isValidProtocol(bytes32 _protocolId) {
        _isValidProtocol(_protocolId);
        _;
    }

    function initialize(address[1] calldata initAddr, uint256 _eobChainId) public initializer {
        __Ownable_init();
        __UUPSUpgradeable_init();
        _setRoleAdmin(ADMIN, ADMIN);
        _grantRole(ADMIN, initAddr[0]);
        eobChainId = _eobChainId;
    }

    function _authorizeUpgrade(address) internal override onlyRole(ADMIN) {}

    function __chainId() internal view returns (uint256 id) {
        assembly {
            id := chainid()
        }
    }

    /*** ADMIN FUNCTIONS ***/

    /// @notice Adding gov contract and first gov transmitters
    /// @param govAddress gov contract address
    /// @param consensusTargetRate consensus target rate for gov protocol
    /// @param govTransmitters initial gov transmitters addresses
    /// @param govExecutors initial gov executors addresses
    /// @param _masterSmartContract address of Master Smart Contract
    /// @param _mscProposeHelper address of MSC Propose Helper (valid only for eob Endpoint)
    function addGov(
        address govAddress,
        uint256 consensusTargetRate,
        address[] calldata govTransmitters,
        address[] calldata govExecutors,
        address _masterSmartContract,
        address _mscProposeHelper
    ) external onlyRole(ADMIN) {
        if (allowedProtocolInfo[govProtocolId].isCreated == true) {
            revert Endpoint__GovAlreadyInited();
        }
        allowedProtocolInfo[govProtocolId].isCreated = true;
        protocolAddressToProtocolId[govAddress] = govProtocolId;
        allowedProtocolInfo[govProtocolId].consensusTargetRate = consensusTargetRate;
        uint i;
        for (; i < govTransmitters.length; i++) {
            if (allowedTransmitters[govProtocolId][govTransmitters[i]]) continue;
            allowedTransmitters[govProtocolId][govTransmitters[i]] = true;
            numberOfAllowedTransmitters[govProtocolId]++;
            emit AddTransmitter(govProtocolId, govTransmitters[i]);
        }
        delete i;
        while (i < govExecutors.length) {
            executors[govProtocolId][govExecutors[i]] = true;
            unchecked {
                ++i;
            }
        }
        govExecutorsCount = govExecutors.length;
        masterSmartContract = abi.encode(_masterSmartContract);
        // only for EOB master sc it's allowed protocol address and msc propose helper is allowed proposer address
        if (__chainId() == eobChainId) {
            allowedProposers[govProtocolId][_mscProposeHelper] = true;
            protocolAddressToProtocolId[_masterSmartContract] = govProtocolId;
        }
        _grantRole(GOV, govAddress);
    }

    /*** GOV FUNCTIONS ***/

    /// @notice Adding protocol to whitelist
    /// @param _protocolId protocol Id
    /// @param _consensusTargetRate consensus target rate
    /// @param _transmitters initial array of transmitters
    function addAllowedProtocol(
        bytes32 _protocolId,
        uint256 _consensusTargetRate,
        address[] calldata _transmitters
    ) external onlyRole(GOV) {
        if (_protocolId == bytes32(0)) {
            revert Endpoint__InvalidProtocolId(_protocolId);
        }
        allowedProtocolInfo[_protocolId].isCreated = true;
        allowedProtocolInfo[_protocolId].consensusTargetRate = _consensusTargetRate;
        for (uint i; i < _transmitters.length; ) {
            if (allowedTransmitters[_protocolId][_transmitters[i]] == false) {
                allowedTransmitters[_protocolId][_transmitters[i]] = true;
                numberOfAllowedTransmitters[_protocolId]++;
                emit AddTransmitter(_protocolId, _transmitters[i]);
            }
            unchecked {
                ++i;
            }
        }
        bytes memory selector = PhotonFunctionSelectorLib.encodeEvmSelector(
            0xba966e5f
        ); // MasterSmartContract.handleAddAllowedProtocol(bytes)
        bytes memory params = abi.encode(_protocolId, __chainId());
        emit Propose(
            govProtocolId,
            PhotonOperationMetaLib.setVersion(0, 1),
            globalNonce++,
            eobChainId,
            masterSmartContract,
            selector,
            params,
            ""
        );
        emit AddAllowedProtocol(_protocolId, _consensusTargetRate, _transmitters);
    }

    /// @notice Adding protocol contract address to whitelist
    /// @param _protocolId protocol id
    /// @param _protocolAddress protocol contract address
    function addAllowedProtocolAddress(
        bytes32 _protocolId,
        address _protocolAddress
    ) external onlyRole(GOV) isValidProtocol(_protocolId) {
        protocolAddressToProtocolId[_protocolAddress] = _protocolId;
        emit AddAllowedProtocolAddress(_protocolId, _protocolAddress);
    }

    /// @notice Removing protocol contract address from whitelist
    /// @param _protocolId protocol id
    /// @param _protocolAddress protocol contract address
    function removeAllowedProtocolAddress(
        bytes32 _protocolId,
        address _protocolAddress
    ) external onlyRole(GOV) isValidProtocol(_protocolId) {
        protocolAddressToProtocolId[_protocolAddress] = bytes32(0);
        emit RemoveAllowedProtocolAddress(_protocolId, _protocolAddress);
    }

    /// @notice Adding proposer to whitelist
    /// @param _proposer address of proposer to add
    function addAllowedProposerAddress(
        bytes32 _protocolId,
        address _proposer
    ) external onlyRole(GOV) isValidProtocol(_protocolId) {
        allowedProposers[_protocolId][_proposer] = true;
        emit AddAllowedProposerAddress(_protocolId, _proposer);
    }

    /// @notice Removing proposer to whitelist
    /// @param _proposer address of proposer to remove
    function removeAllowedProposer(
        bytes32 _protocolId,
        address _proposer
    ) external onlyRole(GOV) isValidProtocol(_protocolId) {
        allowedProposers[_protocolId][_proposer] = false;
        emit RemoveAllowedProposer(_protocolId, _proposer);
    }

    /// @notice Adding executor to whitelist
    /// @param _protocolId protocol id
    /// @param _executor address of executor to add
    function addExecutor(bytes32 _protocolId, address _executor) external onlyRole(GOV) {
        if (executors[_protocolId][_executor]) {
            revert Endpoint__ExecutorIsAlreadyAllowed(_protocolId, _executor);
        }
        if (_protocolId == govProtocolId) {
            govExecutorsCount++;
        }
        executors[_protocolId][_executor] = true;
        emit AddExecutor(_protocolId, _executor);
    }

    /// @notice Removing executor from whitelist
    /// @param _protocolId protocol address
    /// @param _executor address of executor to remove
    function removeExecutor(bytes32 _protocolId, address _executor) external onlyRole(GOV) {
        if (!executors[_protocolId][_executor]) {
            revert Endpoint__ExecutorIsNotAllowed(_protocolId, _executor, _msgSender());
        }
        if (_protocolId == govProtocolId) {
            if (govExecutorsCount <= 1) {
                revert Endpoint__TryingToRemoveLastGovExecutor();
            }
            govExecutorsCount--;
        }
        executors[_protocolId][_executor] = false;
        emit RemoveExecutor(_protocolId, _executor);
    }

    /// @notice Adding transmitters to whitelist (payable is cheaper in gas cost)
    /// @param _protocolId protocol id
    /// @param _transmitters array with addresses of transmitters to add
    function addTransmitters(
        bytes32 _protocolId,
        address[] calldata _transmitters
    ) external payable onlyRole(GOV) {
        for (uint i; i < _transmitters.length; ) {
            if (
                !allowedTransmitters[_protocolId][_transmitters[i]] &&
                _transmitters[i] != address(0)
            ) {
                allowedTransmitters[_protocolId][_transmitters[i]] = true;
                ++numberOfAllowedTransmitters[_protocolId];
                emit AddTransmitter(_protocolId, _transmitters[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Removing transmitters from whitelist (payable is cheaper in gas cost)
    /// @param _protocolId protocol address
    /// @param _transmitters array with addresses of transmitters to remove
    function removeTransmitters(
        bytes32 _protocolId,
        address[] calldata _transmitters
    ) external payable onlyRole(GOV) {
        for (uint i; i < _transmitters.length; ) {
            if (allowedTransmitters[_protocolId][_transmitters[i]]) {
                allowedTransmitters[_protocolId][_transmitters[i]] = false;
                --numberOfAllowedTransmitters[_protocolId];
                emit RemoveTransmitter(_protocolId, _transmitters[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Setting of target rate
    /// @param _protocolId protocol id
    /// @param rate target rate
    function setConsensusTargetRate(bytes32 _protocolId, uint256 rate) external onlyRole(GOV) {
        allowedProtocolInfo[_protocolId].consensusTargetRate = rate;
        emit SetConsensusTargetRate(_protocolId, rate);
    }

    /*** END of GOV FUNCTIONS ***/

    /*** LOGIC FUNCTIONS ***/

    /// @notice Get array of opHashes, check it was executed and returns array of result
    /// @param opHashArray array of operation hashes
    /// @return resultArray array of bool values indicates that operation was executed or not
    function checkOperationsExecuteStatus(
        uint256[] calldata opHashArray
    ) public view returns (bool[] memory resultArray) {
        resultArray = new bool[](opHashArray.length);
        for (uint i; i < opHashArray.length; ) {
            resultArray[i] = opExecutedMap[opHashArray[i]];
            unchecked {
                ++i;
            }
        }
    }

    /// @notice execute approved operation
    /// @param opData 1
    /// @param transmitterSigs 2
    function executeOperation(
        OperationLib.OperationData calldata opData,
        Signature[] calldata transmitterSigs
    ) external payable isAllowedExecutor(opData.protocolAddr) {
        bytes32 msgHash = keccak256(
            abi.encodePacked(
                opData.protocolId,
                opData.meta,
                opData.srcChainId,
                opData.srcBlockNumber,
                opData.srcOpTxId,
                opData.nonce,
                opData.destChainId,
                opData.protocolAddr,
                opData.functionSelector,
                opData.params,
                opData.reserved
            )
        );
        bytes32 opHashBytes = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash)
        );
        uint256 opHash = uint256(opHashBytes);

        if (opData.destChainId != __chainId()) {
            revert Endpoint__OpIsNotForThisChain(opHash);
        }

        if (opExecutedMap[opHash]) {
            revert Endpoint__OpIsAlreadyExecuted(opHash);
        }

        address protocolAddress = abi.decode(opData.protocolAddr, (address));
        bytes32 protocolId = protocolAddressToProtocolId[protocolAddress];

        if (protocolId != opData.protocolId || allowedProtocolInfo[opData.protocolId].isCreated == false) {
            revert Endpoint__InvalidProtocolId(opData.protocolId);
        }

        address[] memory uniqSigners = new address[](transmitterSigs.length);
        uint uniqSignersCnt;
        bool consensusReached;
        uint numOfAllowedTransmitters = numberOfAllowedTransmitters[protocolId];
        if (numOfAllowedTransmitters == 0) {
            revert Endpoint__ZeroTransmittersCount(protocolId);
        }
        uint k;
        uint consensusTargetRate = allowedProtocolInfo[protocolId].consensusTargetRate;
        for (uint i; i < transmitterSigs.length; ) {
            address signer = ecrecover(
                opHashBytes,
                transmitterSigs[i].v,
                transmitterSigs[i].r,
                transmitterSigs[i].s
            );
            if (signer != address(0) && allowedTransmitters[protocolId][signer]) {
                bool isNewSigner = true;
                delete k;
                while (k < uniqSignersCnt) {
                    if (uniqSigners[k] == signer) {
                        isNewSigner = false;
                        break;
                    }
                    unchecked {
                        ++k;
                    }
                }
                if (isNewSigner) {
                    uniqSigners[uniqSignersCnt] = signer;
                    ++uniqSignersCnt;

                    uint256 consensusRate = (uniqSignersCnt * rateDecimals) /
                        numOfAllowedTransmitters;
                    if (consensusRate >= consensusTargetRate) {
                        consensusReached = true;
                        break;
                    }
                }
            }
            unchecked {
                ++i;
            }
        }

        if (consensusReached) {
            (uint8 selectorType, bytes memory selectorDecoded) = PhotonFunctionSelectorLib.decodeFunctionSelector(
                opData.functionSelector
            );
            assert(selectorType == uint8(PhotonFunctionSelectorLib.SelectorTypes.EVM));
            bytes4 selector = abi.decode(selectorDecoded, (bytes4));
            (bool success, bytes memory ret) = protocolAddress.call{value: msg.value}(
                abi.encodeWithSelector(
                    selector,
                    abi.encode(
                        opData.protocolId,
                        opData.srcChainId,
                        opData.srcBlockNumber,
                        opData.srcOpTxId,
                        opData.params
                    )
                )
            );

            if (success) {
                opExecutedMap[opHash] = true;
            }
            else {
                revert Endpoint__TargetCallError(ret);
            }
            emit ProposalExecuted(opHash, success, ret);
        } else {
            revert Endpoint__OpIsNotApproved(opHash);
        }
    }

    function checkProposeData(
        bytes32 protocolId,
        uint protocolAddressLen,
        uint paramsLen
    ) internal pure {
        if (protocolAddressLen > OperationLib.ADDRESS_MAX_LEN) {
            revert Endpoint__AddrTooBig(protocolId);
        }
        if (paramsLen > OperationLib.PARAMS_MAX_LEN) {
            revert Endpoint__ParamsTooBig(protocolId);
        }
    }

    /// @notice Propose a new operation to be executed in the destination chain (no matter execution order)
    /// @param protocolId The protocol ID of the operation
    /// @param destChainId The chain ID the operation is proposed for
    /// @param protocolAddress The protocol contract address in bytes format (abi.encoded address for EVM, and value size for non-EVM up to 128 bytes)
    /// @param functionSelector The function selector to execute (encoded selector with PhotonFunctionSelectorLib)
    /// @param params The payload for the function call
    function propose(
        bytes32 protocolId,
        uint256 destChainId,
        bytes calldata protocolAddress,
        bytes calldata functionSelector,
        bytes calldata params
    ) external isAllowedProposer(protocolId) {
        checkProposeData(
            protocolId,
            protocolAddress.length,
            params.length
        );
        uint256 meta = PhotonOperationMetaLib.setVersion(0, 1);
        meta = PhotonOperationMetaLib.setInOrder(meta, false);
        emit Propose(
            protocolId,
            meta,
            globalNonce++,
            destChainId,
            protocolAddress,
            functionSelector,
            params,
            ""
        );
    }

    /// @notice Propose a new ordered operation to be executed in the destination chain.
    /// This operation will be executed only after the previous one proposed from this chain was completed.
    /// @param protocolId The protocol ID of the operation
    /// @param destChainId The chain ID the operation is proposed for
    /// @param protocolAddress The protocol contract address in bytes format (abi.encoded address for EVM, and value size for non-EVM up to 128 bytes)
    /// @param functionSelector The function selector to execute (encoded selector with PhotonFunctionSelectorLib)
    /// @param params The payload for the function call
    function proposeInOrder(
        bytes32 protocolId,
        uint256 destChainId,
        bytes calldata protocolAddress,
        bytes calldata functionSelector,
        bytes calldata params
    ) external isAllowedProposer(protocolId) {
        checkProposeData(
            protocolId,
            protocolAddress.length,
            params.length
        );
        uint256 meta = PhotonOperationMetaLib.setVersion(0, 1);
        meta = PhotonOperationMetaLib.setInOrder(meta, true);
        emit Propose(
            protocolId,
            meta,
            protocolNonce[protocolId]++,
            destChainId,
            protocolAddress,
            functionSelector,
            params,
            ""
        );
    }
}
