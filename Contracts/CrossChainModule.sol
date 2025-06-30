// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {AMMPool} from "./AMMPool.sol";
import {ICrossChainModule, IPositionManager, ILayerZeroEndpoint, IAxelarGateway, IWormhole, ICrossChainMessenger, ITokenBridge, ICommonStructs} from "./Interfaces.sol";
import {TickMath} from "@uniswap/v3-core/contracts/libraries/TickMath.sol";

// Interface for CrossChainRetryOracle
interface ICrossChainRetryOracle {
    struct NetworkStatus {
        uint64 gasPrice;
        uint32 confirmationTime;
        uint8 congestionLevel;
        bool bridgeOperational;
        uint32 recommendedRetryDelay;
        bool retryRecommended;
        uint256 lastUpdated;
        uint64 randomRetryDelay;
        int256 lastGasPrice;
        int256 lastTokenPrice;
    }

    function getNetworkStatus(uint16 chainId) external view returns (NetworkStatus memory);
    function requestNetworkStatusUpdate(uint16 chainId, bytes32 jobId, uint256 fee) external returns (bytes32);
}

/// @title CrossChainModule
/// @notice Manages cross-chain liquidity addition, token bridging, message validation, and retry mechanisms with oracle integration
/// @dev Interacts with AMMPool for state access and token bridging, secured with access control, uses CrossChainRetryOracle for retry decisions
contract CrossChainModule is ReentrancyGuard {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Constants
    uint256 private constant PRICE_DENOMINATOR = 1e18;
    uint256 private constant MAX_BATCH_SIZE_LIMIT = 100;
    uint256 private constant MIN_GAS_PER_MESSAGE = 100_000;
    uint8 private constant HIGH_CONGESTION_LEVEL = 8;
    uint256 private constant TIMELOCK_DIVISOR = 4;

    // Reference to main AMMPool contract
    AMMPool public immutable pool;

    // Reference to CrossChainRetryOracle contract
    ICrossChainRetryOracle public immutable retryOracle;

    // Chainlink job ID for network status updates
    bytes32 public immutable oracleJobId;

    // LINK token address for oracle requests
    address public immutable linkToken;

    // --- Errors ---
    error Unauthorized();
    error InvalidChainId(uint16 chainId);
    error InvalidAxelarChain(string axelarChain);
    error InvalidNonce(uint64 receivedNonce, uint64 expectedNonce);
    error TimelockNotExpired(uint256 currentTime, uint256 timelock);
    error InvalidAmount(uint256 amountA, uint256 amountB);
    error InvalidToken(address token);
    error InvalidCrossChainMessage(string message);
    error ChainPausedError(uint16 chainId);
    error InvalidAdapterParams();
    error InsufficientFee(uint256 provided, uint256 required);
    error MessengerNotSet(uint8 messengerType);
    error InvalidWormholeVAA();
    error InvalidMessengerType(uint8 messengerType);
    error MaxRetriesExceeded(uint256 messageId);
    error MessageNotFailed(uint256 messageId);
    error RetryNotReady(uint256 messageId, uint256 nextRetryTimestamp);
    error InvalidBatchSize(uint256 size);
    error InsufficientGasForBatch(uint256 required, uint256 provided);
    error InvalidAddress(address addr, string message);
    error InvalidBridgeType(uint8 bridgeType);
    error InvalidMessage();
    error InvalidTickRange(int24 tickLower, int24 tickUpper);
    error OracleNotConfigured(uint16 chainId);
    error RetryNotRecommended(uint16 chainId);
    error InsufficientLinkBalance(uint256 balance, uint256 required);
    error OracleRequestFailed(bytes32 requestId);
    error ZeroPrice();
    error ZeroReserve();
    error NoMessengerConfigured();

    /// @notice Initializes the contract with pool and oracle references
    /// @param _pool Address of the AMMPool contract
    /// @param _retryOracle Address of the CrossChainRetryOracle contract
    /// @param _oracleJobId Chainlink job ID for network status updates
    /// @param _linkToken Address of the LINK token
    constructor(
        address _pool,
        address _retryOracle,
        bytes32 _oracleJobId,
        address _linkToken
    ) {
        if (_pool == address(0)) revert InvalidAddress(_pool, "Invalid pool address");
        if (_retryOracle == address(0)) revert InvalidAddress(_retryOracle, "Invalid oracle address");
        if (_oracleJobId == bytes32(0)) revert InvalidAddress(address(0), "Invalid job ID");
        if (_linkToken == address(0)) revert InvalidAddress(_linkToken, "Invalid LINK token address");
        pool = AMMPool(_pool);
        retryOracle = ICrossChainRetryOracle(_retryOracle);
        oracleJobId = _oracleJobId;
        linkToken = _linkToken;

        // Approve token bridge for maximum allowance
        address tokenBridge = pool.tokenBridge();
        if (tokenBridge != address(0)) {
            IERC20Upgradeable(pool.tokenA()).safeApprove(tokenBridge, type(uint256).max);
            IERC20Upgradeable(pool.tokenB()).safeApprove(tokenBridge, type(uint256).max);
        }
    }

    // --- Modifiers ---

    /// @notice Restricts access to the AMMPool contract
    modifier onlyPool() {
        if (msg.sender != address(pool)) revert Unauthorized();
        _;
    }

    /// @notice Ensures the contract is not paused
    modifier whenNotPaused() {
        if (pool.paused()) revert AMMPool.ContractPaused();
        _;
    }

    /// @notice Ensures the specified chain is not paused
    /// @param chainId The chain ID to check
    modifier whenChainNotPaused(uint16 chainId) {
        if (pool.chainPaused(chainId)) revert ChainPausedError(chainId);
        _;
    }

    // --- External Functions ---

    /// @notice Adds liquidity to a pool on another chain
    /// @param provider The address providing liquidity
    /// @param amountA Amount of tokenA to add
    /// @param amountB Amount of tokenB to add
    /// @param dstChainId The destination chain ID
    /// @param adapterParams Adapter parameters for the cross-chain message
    function addLiquidityCrossChain(
        address provider,
        uint256 amountA,
        uint256 amountB,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyPool whenNotPaused whenChainNotPaused(dstChainId) {
        if (amountA == 0 || amountB == 0) revert InvalidAmount(amountA, amountB);
        if (pool.trustedRemotePools(dstChainId).length == 0) revert InvalidChainId(dstChainId);
        if (adapterParams.length == 0) revert InvalidAdapterParams();

        // Transfer tokens to AMMPool
        IERC20Upgradeable(pool.tokenA()).safeTransferFrom(provider, address(pool), amountA);
        IERC20Upgradeable(pool.tokenB()).safeTransferFrom(provider, address(pool), amountB);

        // Bridge tokens
        _bridgeTokens(pool.tokenA(), amountA, provider, dstChainId);
        _bridgeTokens(pool.tokenB(), amountB, provider, dstChainId);

        // Prepare and send cross-chain message
        string memory axelarChain = pool.chainIdToAxelarChain(dstChainId);
        bytes memory destinationAddress = pool.trustedRemotePools(dstChainId);
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(
            provider,
            amountA,
            amountB,
            nonce,
            block.timestamp + timelock,
            false, // isConcentrated
            int24(0),
            int24(0),
            pool.tokenA(),
            pool.tokenB()
        );

        _sendCrossChainMessage(dstChainId, axelarChain, destinationAddress, payload, adapterParams, nonce, timelock, 0);
        pool.emitCrossChainLiquiditySent(
            provider,
            amountA,
            amountB,
            dstChainId,
            nonce,
            block.timestamp + timelock,
            0
        );
    }

    /// @notice Adds concentrated liquidity to a pool on another chain
    /// @param provider The address providing liquidity
    /// @param amountA Amount of tokenA to add
    /// @param amountB Amount of tokenB to add
    /// @param tickLower The lower tick of the position
    /// @param tickUpper The upper tick of the position
    /// @param dstChainId The destination chain ID
    /// @param adapterParams Adapter parameters for the cross-chain message
    function addConcentratedLiquidityCrossChain(
        address provider,
        uint256 amountA,
        uint256 amountB,
        int24 tickLower,
        int24 tickUpper,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyPool whenNotPaused whenChainNotPaused(dstChainId) {
        if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
        if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);
        if (pool.trustedRemotePools(dstChainId).length == 0) revert InvalidChainId(dstChainId);
        if (adapterParams.length == 0) revert InvalidAdapterParams();

        // Transfer tokens to AMMPool
        IERC20Upgradeable(pool.tokenA()).safeTransferFrom(provider, address(pool), amountA);
        IERC20Upgradeable(pool.tokenB()).safeTransferFrom(provider, address(pool), amountB);

        // Bridge tokens
        _bridgeTokens(pool.tokenA(), amountA, provider, dstChainId);
        _bridgeTokens(pool.tokenB(), amountB, provider, dstChainId);

        // Prepare and send cross-chain message
        string memory axelarChain = pool.chainIdToAxelarChain(dstChainId);
        bytes memory destinationAddress = pool.trustedRemotePools(dstChainId);
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(
            provider,
            amountA,
            amountB,
            nonce,
            block.timestamp + timelock,
            true, // isConcentrated
            tickLower,
            tickUpper,
            pool.tokenA(),
            pool.tokenB()
        );

        _sendCrossChainMessage(dstChainId, axelarChain, destinationAddress, payload, adapterParams, nonce, timelock, 0);
        pool.emitCrossChainLiquiditySent(
            provider,
            amountA,
            amountB,
            dstChainId,
            nonce,
            block.timestamp + timelock,
            0
        );
    }

    /// @notice Executes a cross-chain swap
    /// @param user The user initiating the swap
    /// @param inputToken The input token address
    /// @param amountIn The input amount
    /// @param minAmountOut The minimum output amount
    /// @param dstChainId The destination chain ID
    /// @param adapterParams Adapter parameters
    /// @return amountOut The estimated output amount
    function swapCrossChain(
        address user,
        address inputToken,
        uint256 amountIn,
        uint256 minAmountOut,
        uint16 dstChainId,
        bytes calldata adapterParams
    ) external payable nonReentrant onlyPool whenNotPaused whenChainNotPaused(dstChainId) returns (uint256 amountOut) {
        if (inputToken != pool.tokenA() && inputToken != pool.tokenB()) revert InvalidToken(inputToken);
        if (amountIn == 0) revert InvalidAmount(amountIn, 0);
        if (pool.trustedRemotePools(dstChainId).length == 0) revert InvalidChainId(dstChainId);
        if (adapterParams.length == 0) revert InvalidAdapterParams();

        // Transfer input tokens to AMMPool
        IERC20Upgradeable(inputToken).safeTransferFrom(user, address(pool), amountIn);

        // Bridge tokens
        _bridgeTokens(inputToken, amountIn, user, dstChainId);

        // Prepare and send cross-chain message
        string memory axelarChain = pool.chainIdToAxelarChain(dstChainId);
        bytes memory destinationAddress = pool.trustedRemotePools(dstChainId);
        uint64 nonce = _getNonce(dstChainId, 0);
        uint256 timelock = _getDynamicTimelock(dstChainId);
        bytes memory payload = abi.encode(
            user,
            inputToken,
            amountIn,
            minAmountOut,
            nonce,
            block.timestamp + timelock
        );

        // Estimate output amount
        uint256 lastPrice = pool.lastPrice();
        if (lastPrice == 0) revert ZeroPrice();
        amountOut = (amountIn * lastPrice) / PRICE_DENOMINATOR;

        _sendCrossChainMessage(dstChainId, axelarChain, destinationAddress, payload, adapterParams, nonce, timelock, 0);
        pool.emitCrossChainSwap(
            user,
            inputToken,
            amountIn,
            amountOut,
            dstChainId,
            nonce,
            block.timestamp + timelock,
            _getMessengerType()
        );

        return amountOut;
    }

    /// @notice Receives and processes a cross-chain message
    /// @param srcChainId The source chain ID
    /// @param srcAddress The source address
    /// @param payload The message payload
    /// @param additionalParams Additional parameters for validation
    function receiveMessage(
        uint16 srcChainId,
        bytes calldata srcAddress,
        bytes calldata payload,
        bytes calldata additionalParams
    ) external nonReentrant onlyPool whenNotPaused whenChainNotPaused(srcChainId) {
        _validateCrossChainMessage(srcChainId, srcAddress, payload, additionalParams);

        // Try decoding as a liquidity message (10 components)
        try this.decodeLiquidityPayload(payload) returns (
            address provider,
            uint256 amountA,
            uint256 amountB,
            uint64 nonce,
            uint256 timelock,
            bool isConcentrated,
            int24 tickLower,
            int24 tickUpper,
            address receivedTokenA,
            address receivedTokenB
        ) {
            if (pool.usedNonces(srcChainId, nonce)) revert InvalidNonce(nonce, nonce);
            if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
            if (amountA == 0 && amountB == 0) revert InvalidAmount(amountA, amountB);
            if (isConcentrated && (receivedTokenA != pool.tokenA() || receivedTokenB != pool.tokenB())) revert InvalidToken(receivedTokenA);

            pool.setUsedNonces(srcChainId, nonce, true);

            _receiveBridgedTokens(pool.tokenA(), amountA);
            _receiveBridgedTokens(pool.tokenB(), amountB);

            uint256 liquidity;
            uint256 positionId;
            if (isConcentrated) {
                if (!_isValidTickRange(tickLower, tickUpper)) revert InvalidTickRange(tickLower, tickUpper);
                // Call the wrapper function in AMMPool
                liquidity = pool.getLiquidityForAmounts(tickLower, tickUpper, amountA, amountB, pool.getCurrentTick());
                if (liquidity > type(uint128).max) revert InvalidAmount(liquidity, type(uint128).max);
                positionId = pool.positionCounter();
                
                // Destructure the tuple returned by getFeeGrowthInside
                (uint128 feesOwed0, uint128 feesOwed1) = pool.getFeeGrowthInside(tickLower, tickUpper, positionId);
                
                AMMPool.Position memory position = AMMPool.Position({
                    owner: provider,
                    tickLower: tickLower,
                    tickUpper: tickUpper,
                    liquidity: uint128(liquidity),
                    feeGrowthInside0LastX128: feesOwed0,
                    feeGrowthInside1LastX128: feesOwed1,
                    tokensOwed0: 0,
                    tokensOwed1: 0
                });
                pool.setPosition(positionId, position);
                pool.incrementPositionCounter();
                pool.updateTick(tickLower, liquidity, true);
                pool.updateTick(tickUpper, liquidity, false);
                IPositionManager(pool.positionManager()).mintPosition(positionId, provider);
                pool.emitPositionCreated(positionId, provider, tickLower, tickUpper, uint128(liquidity));
                pool.checkAndMoveToFallback(positionId);
            } else {
                // Fetch reserves as a tuple, not a struct
                (uint64 reserveA, uint64 reserveB) = pool.getReserves();
                if (reserveA == 0 || reserveB == 0) revert ZeroReserve();
                if (pool.totalLiquidity() == 0) {
                    liquidity = _sqrt(amountA * amountB);
                } else {
                    liquidity = (amountA * pool.totalLiquidity()) / reserveA;
                    uint256 liquidityB = (amountB * pool.totalLiquidity()) / reserveB;
                    liquidity = liquidity < liquidityB ? liquidity : liquidityB;
                }
                pool.updateLiquidityBalance(provider, liquidity, true);
                pool.incrementTotalLiquidity(liquidity);
                pool.updateCrossChainReserves(amountA, amountB);
            }

            pool.updateVolatility();
            pool.emitCrossChainLiquidityReceived(provider, amountA, amountB, srcChainId, nonce, _getMessengerType());
        } catch {
            // Try decoding as a swap message (6 components)
            (
                address user,
                address inputToken,
                uint256 amountIn,
                uint256 minAmountOut,
                uint64 nonce,
                uint256 timelock
            ) = abi.decode(payload, (address, address, uint256, uint256, uint64, uint256));

            if (pool.usedNonces(srcChainId, nonce)) revert InvalidNonce(nonce, nonce);
            if (block.timestamp < timelock) revert TimelockNotExpired(block.timestamp, timelock);
            if (inputToken != pool.tokenA() && inputToken != pool.tokenB()) revert InvalidToken(inputToken);
            if (amountIn == 0) revert InvalidAmount(amountIn, 0);

            pool.setUsedNonces(srcChainId, nonce, true);

            _receiveBridgedTokens(inputToken, amountIn);

            // Perform the swap
            uint256 amountOut = pool.swap(inputToken, amountIn, minAmountOut, user);
            pool.emitCrossChainSwap(
                user,
                inputToken,
                amountIn,
                amountOut,
                srcChainId,
                nonce,
                timelock,
                _getMessengerType()
            );
        }
    }

    // Helper function to decode liquidity payload
    function decodeLiquidityPayload(bytes calldata payload)
        external
        pure
        returns (
            address provider,
            uint256 amountA,
            uint256 amountB,
            uint64 nonce,
            uint256 timelock,
            bool isConcentrated,
            int24 tickLower,
            int24 tickUpper,
            address receivedTokenA,
            address receivedTokenB
        )
    {
        return abi.decode(payload, (address, uint256, uint256, uint64, uint256, bool, int24, int24, address, address));
    }

    /// @notice Sends batched cross-chain messages
    /// @param dstChainIds Array of destination chain IDs
    /// @param dstAxelarChains Array of destination Axelar chain names
    /// @param payloads Array of message payloads
    /// @param adapterParams Array of adapter parameters
    /// @param timelocks Array of timelocks for messages
    function batchCrossChainMessages(
        uint16[] calldata dstChainIds,
        string[] calldata dstAxelarChains,
        bytes[] calldata payloads,
        bytes[] calldata adapterParams,
        uint256[] calldata timelocks
    ) external payable nonReentrant onlyPool whenNotPaused {
        _batchCrossChainMessages(dstChainIds, dstAxelarChains, payloads, adapterParams, timelocks, _getMessengerType());
    }

    /// @notice Retries a single failed cross-chain message
    /// @param messageId The ID of the failed message
    function retryFailedMessage(uint256 messageId) external payable nonReentrant onlyPool {
        ICommonStructs.FailedMessage memory message = pool.getFailedMessage(messageId);
        if (message.retries >= pool.MAX_RETRIES()) revert MaxRetriesExceeded(messageId);
        if (message.timestamp == 0) revert MessageNotFailed(messageId);
        if (block.timestamp < message.nextRetryTimestamp) revert RetryNotReady(messageId, message.nextRetryTimestamp);

        // Consult oracle for retry recommendation
        ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(message.dstChainId);
        if (!status.retryRecommended || !status.bridgeOperational) revert RetryNotRecommended(message.dstChainId);

        address messenger = pool.crossChainMessengers(message.messengerType);
        if (messenger == address(0)) revert MessengerNotSet(message.messengerType);

        (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
            message.dstChainId,
            message.dstAxelarChain,
            address(pool),
            message.payload,
            message.adapterParams
        );
        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        bool success;
        try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
            message.dstChainId,
            message.dstAxelarChain,
            pool.trustedRemotePools(message.dstChainId),
            message.payload,
            message.adapterParams,
            payable(msg.sender)
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
            success = true;
            pool.emitFailedMessageRetried(messageId, message.dstChainId, message.retries + 1, message.messengerType);
        } catch {
            // Use oracle-recommended retry delay
            uint256 nextRetryTimestamp = block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay);
            pool.emitFailedMessageRetryScheduled(messageId, nextRetryTimestamp);
        }

        if (success) {
            pool.deleteFailedMessage(messageId);
        } else {
            pool.updateFailedMessage(
                messageId,
                message.retries + 1,
                block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay)
            );
        }
    }

    /// @notice Retries multiple failed cross-chain messages in a batch
    /// @param messageIds Array of failed message IDs
    function retryFailedMessagesBatch(uint256[] calldata messageIds) external payable nonReentrant onlyPool {
        if (messageIds.length == 0 || messageIds.length > pool.MAX_BATCH_SIZE() || messageIds.length > MAX_BATCH_SIZE_LIMIT) {
            revert InvalidBatchSize(messageIds.length);
        }

        uint256 totalNativeFee;
        uint256 successfulRetries;
        uint256 failedRetries;
        uint256[] memory processedIds = new uint256[](messageIds.length);

        // Estimate total fees and check oracle status
        for (uint256 i = 0; i < messageIds.length; i++) {
            ICommonStructs.FailedMessage memory message = pool.getFailedMessage(messageIds[i]);
            if (message.retries >= pool.MAX_RETRIES() || message.timestamp == 0 || block.timestamp < message.nextRetryTimestamp) continue;

            // Consult oracle for retry recommendation
            ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(message.dstChainId);
            if (!status.retryRecommended || !status.bridgeOperational) continue;

            address messenger = pool.crossChainMessengers(message.messengerType);
            if (messenger == address(0)) continue;

            (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
                message.dstChainId,
                message.dstAxelarChain,
                address(pool),
                message.payload,
                message.adapterParams
            );
            totalNativeFee += nativeFee;
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);

        uint256 gasPerMessage = MIN_GAS_PER_MESSAGE;
        uint256 refundAmount = msg.value;

        // Process retries
        for (uint256 i = 0; i < messageIds.length; i++) {
            if (gasleft() < gasPerMessage) revert InsufficientGasForBatch(gasPerMessage, gasleft());

            ICommonStructs.FailedMessage memory message = pool.getFailedMessage(messageIds[i]);
            if (message.retries >= pool.MAX_RETRIES() || message.timestamp == 0 || block.timestamp < message.nextRetryTimestamp) {
                failedRetries++;
                continue;
            }

            // Consult oracle for retry recommendation
            ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(message.dstChainId);
            if (!status.retryRecommended || !status.bridgeOperational) {
                failedRetries++;
                continue;
            }

            address messenger = pool.crossChainMessengers(message.messengerType);
            if (messenger == address(0)) {
                failedRetries++;
                continue;
            }

            (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
                message.dstChainId,
                message.dstAxelarChain,
                address(pool),
                message.payload,
                message.adapterParams
            );

            bool success;
            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                message.dstChainId,
                message.dstAxelarChain,
                pool.trustedRemotePools(message.dstChainId),
                message.payload,
                message.adapterParams,
                payable(msg.sender)
            ) {
                success = true;
                refundAmount -= nativeFee;
                successfulRetries++;
                processedIds[i] = messageIds[i];
                pool.emitFailedMessageRetried(messageIds[i], message.dstChainId, message.retries + 1, message.messengerType);
            } catch {
                failedRetries++;
                uint256 nextRetryTimestamp = block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay);
                pool.emitFailedMessageRetryScheduled(messageIds[i], nextRetryTimestamp);
            }

            if (success) {
                pool.deleteFailedMessage(messageIds[i]);
            } else {
                pool.updateFailedMessage(
                    messageIds[i],
                    message.retries + 1,
                    block.timestamp + (status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay)
                );
            }
        }

        if (refundAmount > 0) {
            payable(msg.sender).transfer(refundAmount);
        }

        pool.emitBatchRetryProcessed(processedIds, successfulRetries, failedRetries);
    }

    /// @notice Requests a network status update from the oracle
    /// @param chainId The target chain ID
    /// @param fee The LINK fee for the request
    /// @return requestId The Chainlink request ID
    function requestOracleNetworkStatusUpdate(uint16 chainId, uint256 fee) external onlyPool returns (bytes32 requestId) {
        uint256 linkBalance = IERC20Upgradeable(linkToken).balanceOf(address(this));
        if (linkBalance < fee) revert InsufficientLinkBalance(linkBalance, fee);

        try retryOracle.requestNetworkStatusUpdate(chainId, oracleJobId, fee) returns (bytes32 _requestId) {
            requestId = _requestId;
        } catch {
            revert OracleRequestFailed(bytes32(0));
        }
    }

    // --- Internal Functions ---

    /// @notice Bridges tokens to another chain
    /// @param token The token address
    /// @param amount The amount to bridge
    /// @param recipient The recipient on the destination chain
    /// @param dstChainId The destination chain ID
    function _bridgeTokens(address token, uint256 amount, address recipient, uint16 dstChainId) internal {
        uint8 bridgeType = pool.tokenBridgeType(token);
        if (bridgeType == 0) revert InvalidBridgeType(bridgeType);

        address tokenBridge = pool.tokenBridge();
        if (bridgeType == 1) {
            ITokenBridge(tokenBridge).burn(token, amount, recipient, dstChainId);
        } else if (bridgeType == 2) {
            ITokenBridge(tokenBridge).lock(token, amount, recipient, dstChainId);
        } else {
            revert InvalidBridgeType(bridgeType);
        }
    }

    /// @notice Receives bridged tokens
    /// @param token The token address
    /// @param amount The amount to receive
    function _receiveBridgedTokens(address token, uint256 amount) internal {
        uint8 bridgeType = pool.tokenBridgeType(token);
        if (bridgeType == 0) revert InvalidBridgeType(bridgeType);

        address tokenBridge = pool.tokenBridge();
        if (bridgeType == 1) {
            ITokenBridge(tokenBridge).mint(token, amount, address(pool));
        } else if (bridgeType == 2) {
            ITokenBridge(tokenBridge).release(token, amount, address(pool));
        } else {
            revert InvalidBridgeType(bridgeType);
        }
    }

    /// @notice Sends a cross-chain message
    /// @param dstChainId The destination chain ID
    /// @param axelarChain The destination Axelar chain name
    /// @param destinationAddress The destination address
    /// @param payload The message payload
    /// @param adapterParams Adapter parameters
    /// @param nonce The message nonce
    /// @param timelock The timelock for the message
    /// @param messengerType The messenger type
    function _sendCrossChainMessage(
        uint16 dstChainId,
        string memory axelarChain,
        bytes memory destinationAddress,
        bytes memory payload,
        bytes memory adapterParams,
        uint64 nonce,
        uint256 timelock,
        uint8 messengerType
    ) internal {
        if (adapterParams.length == 0) revert InvalidAdapterParams();
        address messenger = pool.crossChainMessengers(messengerType);
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
            dstChainId,
            axelarChain,
            address(pool),
            payload,
            adapterParams
        );

        if (msg.value < nativeFee) revert InsufficientFee(msg.value, nativeFee);

        try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
            dstChainId,
            axelarChain,
            destinationAddress,
            payload,
            adapterParams,
            payable(msg.sender)
        ) {
            if (msg.value > nativeFee) {
                payable(msg.sender).transfer(msg.value - nativeFee);
            }
        } catch {
            // Consult oracle for retry delay
            ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(dstChainId);
            uint256 retryDelay = status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay;
            uint256 messageId = pool.failedMessageCount();
            pool.setFailedMessage(
                messageId,
                ICommonStructs.FailedMessage({
                    dstChainId: dstChainId,
                    dstAxelarChain: axelarChain,
                    payload: payload,
                    adapterParams: adapterParams,
                    retries: 0,
                    timestamp: block.timestamp,
                    messengerType: messengerType,
                    nextRetryTimestamp: block.timestamp + retryDelay
                })
            );
            pool.incrementFailedMessageCount();
            pool.emitFailedMessageStored(messageId, dstChainId, axelarChain, block.timestamp, messengerType);
        }
    }

    /// @notice Validates a cross-chain message
    /// @param srcChainId The source chain ID
    /// @param srcAddress The source address
    /// @param payload The message payload
    /// @param additionalParams Additional parameters for validation
    function _validateCrossChainMessage(
        uint16 srcChainId,
        bytes memory srcAddress,
        bytes memory payload,
        bytes memory additionalParams
    ) internal {
        bytes32 messageHash = keccak256(abi.encode(srcChainId, srcAddress, payload));
        if (pool.validatedMessages(messageHash)) revert InvalidCrossChainMessage("Message already processed");
        pool.setValidatedMessages(messageHash, true);

        bytes memory trustedAddress = pool.trustedRemotePools(srcChainId);
        if (trustedAddress.length == 0 || keccak256(srcAddress) != keccak256(trustedAddress)) {
            revert InvalidCrossChainMessage("Untrusted source address");
        }

        uint8 messengerType = _getMessengerType();
        address messenger = pool.crossChainMessengers(messengerType);
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        if (messengerType == 0) {
            // LayerZero
            uint64 nonce = ILayerZeroEndpoint(messenger).getInboundNonce(srcChainId, srcAddress);
            if (nonce == 0) revert InvalidNonce(nonce, 1);
        } else if (messengerType == 1) {
            // Axelar
            bytes32 payloadHash = keccak256(payload);
            bool valid = IAxelarGateway(messenger).validateContractCall(
                bytes32(additionalParams),
                pool.chainIdToAxelarChain(srcChainId),
                string(srcAddress),
                payloadHash
            );
            if (!valid) revert InvalidCrossChainMessage("Invalid Axelar message");
        } else if (messengerType == 2) {
            // Wormhole
            (uint16 emitterChainId, bytes32 emitterAddress, uint64 sequence, bytes memory wormholePayload) = IWormhole(messenger).parseAndVerifyVM(additionalParams);
            if (emitterChainId != srcChainId || emitterAddress != pool.wormholeTrustedSenders(srcChainId)) {
                revert InvalidWormholeVAA();
            }
            if (keccak256(wormholePayload) != keccak256(payload)) {
                revert InvalidWormholeVAA();
            }
        } else {
            revert InvalidMessengerType(messengerType);
        }
    }

    /// @notice Processes batched cross-chain messages
    /// @param dstChainIds Array of destination chain IDs
    /// @param dstAxelarChains Array of destination Axelar chain names
    /// @param payloads Array of message payloads
    /// @param adapterParams Array of adapter parameters
    /// @param timelocks Array of timelocks for messages
    /// @param messengerType Type of messenger to use
    function _batchCrossChainMessages(
        uint16[] memory dstChainIds,
        string[] memory dstAxelarChains,
        bytes[] memory payloads,
        bytes[] memory adapterParams,
        uint256[] memory timelocks,
        uint8 messengerType
    ) internal {
        uint256 batchSize = dstChainIds.length;
        if (batchSize == 0 || batchSize > pool.MAX_BATCH_SIZE() || batchSize > MAX_BATCH_SIZE_LIMIT) revert InvalidBatchSize(batchSize);
        if (
            batchSize != dstAxelarChains.length ||
            batchSize != payloads.length ||
            batchSize != adapterParams.length ||
            batchSize != timelocks.length
        ) revert InvalidBatchSize(batchSize);

        address messenger = pool.crossChainMessengers(messengerType);
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        uint256 totalNativeFee;
        for (uint256 i = 0; i < batchSize; ++i) {
            if (pool.trustedRemotePools(dstChainIds[i]).length == 0) revert InvalidChainId(dstChainIds[i]);
            if (bytes(dstAxelarChains[i]).length == 0) revert InvalidAxelarChain(dstAxelarChains[i]);
            if (payloads[i].length == 0) revert InvalidMessage();
            if (pool.chainPaused(dstChainIds[i])) revert ChainPausedError(dstChainIds[i]);
            if (adapterParams[i].length == 0) revert InvalidAdapterParams();
            if (keccak256(bytes(pool.chainIdToAxelarChain(dstChainIds[i]))) != keccak256(bytes(dstAxelarChains[i]))) {
                revert InvalidAxelarChain(dstAxelarChains[i]);
            }

            (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
                dstChainIds[i],
                dstAxelarChains[i],
                address(pool),
                payloads[i],
                adapterParams[i]
            );
            totalNativeFee += nativeFee;
        }

        if (msg.value < totalNativeFee) revert InsufficientFee(msg.value, totalNativeFee);

        uint256 gasPerMessage = MIN_GAS_PER_MESSAGE;
        uint256 refundAmount = msg.value;

        for (uint256 i = 0; i < batchSize; ++i) {
            if (gasleft() < gasPerMessage) revert InsufficientGasForBatch(gasPerMessage, gasleft());

            uint64 nonce = _getNonce(dstChainIds[i], messengerType);
            bytes memory modifiedPayload = abi.encode(abi.decode(payloads[i], (bytes)), nonce);

            (uint256 nativeFee, ) = ICrossChainMessenger(messenger).estimateFees(
                dstChainIds[i],
                dstAxelarChains[i],
                address(pool),
                modifiedPayload,
                adapterParams[i]
            );

            try ICrossChainMessenger(messenger).sendMessage{value: nativeFee}(
                dstChainIds[i],
                dstAxelarChains[i],
                pool.trustedRemotePools(dstChainIds[i]),
                modifiedPayload,
                adapterParams[i],
                payable(msg.sender)
            ) {
                refundAmount -= nativeFee;
            } catch {
                // Consult oracle for retry delay
                ICrossChainRetryOracle.NetworkStatus memory status = _getOracleNetworkStatus(dstChainIds[i]);
                uint256 retryDelay = status.randomRetryDelay > 0 ? status.randomRetryDelay : status.recommendedRetryDelay;
                uint256 messageId = pool.failedMessageCount();
                pool.setFailedMessage(
                    messageId,
                    ICommonStructs.FailedMessage({
                        dstChainId: dstChainIds[i],
                        dstAxelarChain: dstAxelarChains[i],
                        payload: modifiedPayload,
                        adapterParams: adapterParams[i],
                        retries: 0,
                        timestamp: block.timestamp,
                        messengerType: messengerType,
                        nextRetryTimestamp: block.timestamp + retryDelay
                    })
                );
                pool.incrementFailedMessageCount();
                pool.emitFailedMessageStored(
                    messageId,
                    dstChainIds[i],
                    dstAxelarChains[i],
                    block.timestamp,
                    messengerType
                );
            }
        }

        if (refundAmount > 0) {
            payable(msg.sender).transfer(refundAmount);
        }

        pool.emitBatchMessagesSent(dstChainIds, messengerType, totalNativeFee - refundAmount);
    }

    /// @notice Gets the nonce for a cross-chain message
    /// @param chainId The chain ID
    /// @param messengerType The messenger type
    /// @return nonce The nonce
    function _getNonce(uint16 chainId, uint8 messengerType) internal view returns (uint64 nonce) {
        address messenger = pool.crossChainMessengers(messengerType);
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        if (messengerType == 0) {
            nonce = ILayerZeroEndpoint(messenger).getInboundNonce(chainId, pool.trustedRemotePools(chainId));
        } else if (messengerType == 2) {
            nonce = uint64(block.timestamp % type(uint64).max);
        } else {
            nonce = uint64(block.timestamp);
        }
    }

    /// @notice Gets the dynamic timelock for a chain
    /// @param chainId The chain ID
    /// @return timelock The timelock
    function _getDynamicTimelock(uint16 chainId) internal view returns (uint256 timelock) {
        timelock = pool.chainTimelocks(chainId);
        if (timelock < pool.MIN_TIMELOCK() || timelock > pool.MAX_TIMELOCK()) {
            timelock = pool.MIN_TIMELOCK();
        }
        if (timelock == 0) revert InvalidAmount(timelock, 0);
        if (pool.emaVolatility() > pool.getVolatilityThreshold()) {
            timelock += timelock / 2;
            if (timelock > pool.MAX_TIMELOCK()) timelock = pool.MAX_TIMELOCK();
        }

        // Adjust timelock based on oracle network status
        try retryOracle.getNetworkStatus(chainId) returns (ICrossChainRetryOracle.NetworkStatus memory status) {
            if (status.congestionLevel >= HIGH_CONGESTION_LEVEL) {
                timelock += timelock / TIMELOCK_DIVISOR; // Increase timelock by 25% for high congestion
                if (timelock > pool.MAX_TIMELOCK()) timelock = pool.MAX_TIMELOCK();
            }
        } catch {
            // Fallback to default timelock without emitting event, as OracleQueryFailed is not defined in IAMMPool
        }
    }

    /// @notice Computes the square root of a uint256 using the Babylonian method
    /// @param y The number to compute the square root of
    /// @return z The square root of y
    function _sqrt(uint256 y) internal pure returns (uint256 z) {
        if (y > 3) {
            z = y;
            uint256 x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
        // else z = 0 (default)
    }

    /// @notice Validates tick range for concentrated liquidity
    /// @param tickLower The lower tick
    /// @param tickUpper The upper tick
    /// @return valid True if valid
    function _isValidTickRange(int24 tickLower, int24 tickUpper) internal view returns (bool valid) {
        return
            tickLower < tickUpper &&
            tickLower % int24(pool.getTickSpacing()) == 0 &&
            tickUpper % int24(pool.getTickSpacing()) == 0 &&
            tickLower >= TickMath.MIN_TICK &&
            tickUpper <= TickMath.MAX_TICK;
    }

    function _isInRange(int24 currentTick, int24 tickLower, int24 tickUpper) internal pure returns (bool) {
        return currentTick >= tickLower && currentTick < tickUpper;
    }

    /// @notice Retrieves network status from the oracle
    /// @param chainId The target chain ID
    /// @return status The network status
    function _getOracleNetworkStatus(uint16 chainId) internal view returns (ICrossChainRetryOracle.NetworkStatus memory status) {
        try retryOracle.getNetworkStatus(chainId) returns (ICrossChainRetryOracle.NetworkStatus memory _status) {
            status = _status;
        } catch {
            revert OracleNotConfigured(chainId);
        }
    }

    /// @notice Gets the default messenger type
    /// @return messengerType The messenger type (0 for LayerZero, 1 for Axelar, 2 for Wormhole)
    function _getMessengerType() internal view returns (uint8 messengerType) {
        // Check available messengers in priority order: LayerZero (0), Axelar (1), Wormhole (2)
        if (pool.crossChainMessengers(0) != address(0)) {
            return 0; // LayerZero
        } else if (pool.crossChainMessengers(1) != address(0)) {
            return 1; // Axelar
        } else if (pool.crossChainMessengers(2) != address(0)) {
            return 2; // Wormhole
        } else {
            revert NoMessengerConfigured();
        }
    }

    /// @notice Estimates cross-chain message fees
    /// @param dstChainId The destination chain ID
    /// @param payload The message payload
    /// @param adapterParams Adapter parameters
    /// @return nativeFee The estimated native fee
    /// @return zroFee The estimated ZRO fee
    function getEstimatedCrossChainFee(
        uint16 dstChainId,
        bytes calldata payload,
        bytes calldata adapterParams
    ) external view returns (uint256 nativeFee, uint256 zroFee) {
        uint8 messengerType = _getMessengerType();
        address messenger = pool.crossChainMessengers(messengerType);
        if (messenger == address(0)) revert MessengerNotSet(messengerType);

        string memory axelarChain = pool.chainIdToAxelarChain(dstChainId);
        return ICrossChainMessenger(messenger).estimateFees(
            dstChainId,
            axelarChain,
            address(pool),
            payload,
            adapterParams
        );
    }
}