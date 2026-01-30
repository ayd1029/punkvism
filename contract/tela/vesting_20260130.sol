// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract VestingContract is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant SCHEDULER_ROLE = keccak256("SCHEDULER_ROLE");

    uint256 public constant MAX_PLANS = 52;

    struct TokenInfo {
        string tokenName;
        string tokenSymbol;
        uint256 totalSupply;
        address token; // ERC20
        address mintWalletAddress; // 수령지 허용용
        bool exists;
    }

    struct Vesting {
        address beneficiary;
        address token; // ERC20 address
        uint64 vestingId;
        uint256 totalAmount;
        uint256 releasedAmount;
        uint64 startTime;
        uint64 endTime;
        uint64 lastReleaseTime;
        string category;
        bool isActive;
        address destination; // 기본 수령지
        bytes32 parentKey; 
        uint256 remainingReserved; // “컨트랙트가 실제로 보유한 토큰 중 이 vesting에 예약된 잔액”
    }

    struct YearlyPlan {
        uint64 releaseTime; // seconds
        uint256 amount; // smallest units
        bool released;
    }

    struct YearlyPlanInput {
        uint64 releaseTime;
        uint256 amount;
        bool released; // 대부분 false로 넣는 걸 권장
    }

    mapping(address => TokenInfo) public tokenInfoByToken; // token => info
    mapping(bytes32 => Vesting) private vestingByKey;

    mapping(bytes32 => YearlyPlan[]) private plansByKey;
    mapping(bytes32 => mapping(uint64 => uint256)) private planIndexPlus1ByKey; // releaseTime => index+1

    mapping(address => uint256) public globalReserved; // token => sum(remainingReserved)

    event DeployerInitialized(address indexed deployer);
    event AdminInitialized(address indexed admin);
    event TokenInfoInitialized(
        address indexed token,
        address indexed mintWallet
    );
    event Locked(address indexed token, address indexed from, uint256 amount);

    event VestingCreated(
        bytes32 indexed key,
        address indexed beneficiary,
        address indexed token,
        uint64 vestingId,
        bytes32 parentKey
    );
    event PlansAppended(bytes32 indexed key, uint256 appendedCount);
    event PlansReplaced(bytes32 indexed key, uint256 newCount);

    event VestingExecuted(
        bytes32 indexed key,
        uint64 releaseTime,
        uint256 amount,
        address indexed destination
    );
    event EmergencyStopToggled(bytes32 indexed key, bool isActive);

    error Unauthorized();
    error InvalidParameters();
    error NotActive();
    error VestingNotReached();
    error AlreadyReleased();
    error InvalidToken();
    error InsufficientAmount();
    error InsufficientSpace();

    constructor(address deployer) {
        _grantRole(DEFAULT_ADMIN_ROLE, deployer);
        _grantRole(DEPLOYER_ROLE, deployer);
        emit DeployerInitialized(deployer);
    }

    function vestingKey(
        address beneficiary,
        address token,
        uint64 vestingId
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(beneficiary, token, vestingId));
    }

    // --------- Admin / Token Registry ---------
    function initialize(address admin) external onlyRole(DEPLOYER_ROLE) {
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(SCHEDULER_ROLE, admin); // 기본: admin이 스케줄러 권한도 가짐
        emit AdminInitialized(admin);
    }

    // 스케줄러 지갑 주소 수정
    function setScheduler(
        address scheduler,
        bool enabled
    ) external onlyRole(ADMIN_ROLE) {
        if (enabled) _grantRole(SCHEDULER_ROLE, scheduler);
        else _revokeRole(SCHEDULER_ROLE, scheduler);
    }

    function initTokenInfo(
        address token,
        string calldata tokenName,
        string calldata tokenSymbol,
        uint256 totalSupply,
        address mintWalletAddress
    ) external onlyRole(ADMIN_ROLE) {
        if (token == address(0) || mintWalletAddress == address(0))
            revert InvalidParameters();
        tokenInfoByToken[token] = TokenInfo({
            tokenName: tokenName,
            tokenSymbol: tokenSymbol,
            totalSupply: totalSupply,
            token: token,
            mintWalletAddress: mintWalletAddress,
            exists: true
        });
        emit TokenInfoInitialized(token, mintWalletAddress);
    }

    // ERC20을 컨트랙트로 예치
    function lockupVault(
        address token,
        uint256 amount
    ) external onlyRole(ADMIN_ROLE) {
        if (!tokenInfoByToken[token].exists) revert InvalidToken();
        if (amount == 0) revert InvalidParameters();
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Locked(token, msg.sender, amount);
    }

    // --------- Vesting CRUD ---------
    function getVesting(bytes32 childKey) external view returns (Vesting memory) {
        return vestingByKey[childKey];
    }

    function getPlans(bytes32 childKey) external view returns (YearlyPlan[] memory) {
        return plansByKey[childKey];
    }

    function createVesting(
        address beneficiary,
        address token,
        uint64 vestingId,
        uint256 totalAmount,
        uint256 releasedAmount,
        uint64 startTime,
        uint64 endTime,
        string calldata category,
        address destination
    ) external onlyRole(ADMIN_ROLE) {
        if (!tokenInfoByToken[token].exists) revert InvalidToken();
        if (beneficiary == address(0) || destination == address(0))
            revert InvalidParameters();
        if (totalAmount == 0 || releasedAmount > totalAmount)
            revert InvalidParameters();

        bytes32 childKey = vestingKey(beneficiary, token, vestingId);
        if (vestingByKey[childKey].beneficiary != address(0))
            revert InvalidParameters();

        uint256 remaining = totalAmount - releasedAmount;
        uint256 available = IERC20(token).balanceOf(address(this)) -
            globalReserved[token];
        if (available < remaining) revert InsufficientAmount();

        vestingByKey[childKey] = Vesting({
            beneficiary: beneficiary,
            token: token,
            vestingId: vestingId,
            totalAmount: totalAmount,
            releasedAmount: releasedAmount,
            startTime: startTime,
            endTime: endTime,
            lastReleaseTime: 0,
            category: category,
            isActive: true,
            destination: destination,
            parentKey: bytes32(0),
            remainingReserved: remaining
        });

        globalReserved[token] += remaining;

        emit VestingCreated(childKey, beneficiary, token, vestingId, bytes32(0));
    }

    // child vesting: parent에서 예약분을 이관
    function userCreateVesting(
        bytes32 parentKey,
        address beneficiary,
        address token,
        uint64 vestingId,
        uint256 totalAmount,
        uint256 releasedAmount,
        uint64 startTime,
        uint64 endTime,
        string calldata category,
        address destination
    ) external onlyRole(ADMIN_ROLE) {
        if (!tokenInfoByToken[token].exists) revert InvalidToken();
        if (beneficiary == address(0) || destination == address(0))
            revert InvalidParameters();
        if (totalAmount == 0 || releasedAmount > totalAmount)
            revert InvalidParameters();

        Vesting storage parent = vestingByKey[parentKey];
        if (parent.beneficiary == address(0) || !parent.isActive)
            revert InvalidParameters();
        if (parent.token != token) revert InvalidParameters();

        bytes32 childKey = vestingKey(beneficiary, token, vestingId);
        if (vestingByKey[childKey].beneficiary != address(0))
            revert InvalidParameters();

        uint256 remaining = totalAmount - releasedAmount;
        if (parent.remainingReserved < remaining) revert InsufficientAmount();

        parent.remainingReserved -= remaining;

        Vesting storage v = vestingByKey[childKey];
            v.beneficiary = beneficiary;
            v.token = token;
            v.vestingId = vestingId;
            v.totalAmount = totalAmount;
            v.releasedAmount = releasedAmount;
            v.startTime = startTime;
            v.endTime = endTime;
            v.lastReleaseTime = 0;
            v.category = category;
            v.isActive = true;
            v.destination = destination;
            v.parentKey = parentKey;
            v.remainingReserved = remaining;

        // globalReserved는 변하지 않음(부모→자식 이관)
        // emit VestingCreated(childKey, beneficiary, token, vestingId, parentKey);
        _emitVestingCreated(childKey);
    }

    function emergencyStop(bytes32 key) external onlyRole(ADMIN_ROLE) {
        Vesting storage v = vestingByKey[key];
        if (v.beneficiary == address(0)) revert InvalidParameters();
        v.isActive = !v.isActive;
        emit EmergencyStopToggled(key, v.isActive);
    }

    // --------- Plan Management ---------
    function appendYearlyPlan(
        bytes32 childKey,
        YearlyPlanInput[] calldata inputs,
        bytes32 parentKeyIfAny
    ) external onlyRole(ADMIN_ROLE) {
        Vesting storage v = vestingByKey[childKey];
        if (v.beneficiary == address(0)) revert InvalidParameters();
        if (inputs.length == 0 || inputs.length > MAX_PLANS)
            revert InvalidParameters();

        // 입력 검증 + strict increasing
        uint64 nowTs = uint64(block.timestamp);
        uint64 lastRt = 0; // inputs가 시간 순서대로 증가하는지 검증하는데 쓰임
        if (plansByKey[childKey].length > 0) {
            lastRt = plansByKey[childKey][plansByKey[childKey].length - 1].releaseTime;
        }
        uint256 totalAdd = 0;
        for (uint256 i = 0; i < inputs.length; i++) {
            if (inputs[i].amount == 0 || inputs[i].releaseTime == 0)
                revert InvalidParameters();
            if (inputs[i].releaseTime <= lastRt) revert InvalidParameters();
            if (i > 0 && inputs[i].releaseTime <= inputs[i - 1].releaseTime)
                revert InvalidParameters();
            if (inputs[i].releaseTime + 3650 days < nowTs)
                revert InvalidParameters();
            totalAdd += inputs[i].amount;
        }

        if (plansByKey[childKey].length + inputs.length > MAX_PLANS)
            revert InsufficientSpace();

        // 부모 플랜에서 차감
        bytes32 parentKey = v.parentKey != bytes32(0)
            ? v.parentKey
            : parentKeyIfAny;
        if (parentKey != bytes32(0)) {
            _deductFromParentPlans(parentKey, inputs);
        }

        for (uint256 i = 0; i < inputs.length; i++) {
            plansByKey[childKey].push(
                YearlyPlan({
                    releaseTime: inputs[i].releaseTime,
                    amount: inputs[i].amount,
                    released: inputs[i].released
                })
            );
            planIndexPlus1ByKey[childKey][inputs[i].releaseTime] = plansByKey[childKey]
                .length; // index+1
        }

        emit PlansAppended(childKey, inputs.length);
    }

    function updatePlanChunk(
        bytes32 childKey,
        YearlyPlanInput[] calldata newPlans,
        bytes32 parentKeyIfAny
    ) external onlyRole(ADMIN_ROLE) {
        Vesting storage v = vestingByKey[childKey];
        if (v.beneficiary == address(0)) revert InvalidParameters();
        if (newPlans.length > MAX_PLANS) revert InsufficientSpace();

        bytes32 parentKey = v.parentKey != bytes32(0)
            ? v.parentKey
            : parentKeyIfAny;
        if (parentKey != bytes32(0)) {
            // 기존 child 플랜을 parent에 반납 후, 새 플랜으로 다시 차감
            _returnToParentPlans(parentKey, plansByKey[childKey]);
            _deductFromParentPlans(parentKey, newPlans);
        }

        // 기존 releaseTIme 인덱스 매핑 정리 (스테일 인덱스 방지)
        YearlyPlan[] storage oldPlans = plansByKey[childKey];
        for (uint256 i = 0; i < oldPlans.length; i++) {
            planIndexPlus1ByKey[childKey][oldPlans[i].releaseTime] = 0;
        }
        
        // 기존 플랜 삭제
        delete plansByKey[childKey];

        // 새 플랜 재구성 + 인덱스 매핑 재생성
        uint64 lastRt = 0;
        for (uint256 i = 0; i < newPlans.length; i++) {
            if (newPlans[i].amount == 0 || newPlans[i].releaseTime == 0)
                revert InvalidParameters();
            if (i > 0 && newPlans[i].releaseTime <= newPlans[i - 1].releaseTime)
                revert InvalidParameters();
            if (newPlans[i].releaseTime <= lastRt) revert InvalidParameters();
            lastRt = newPlans[i].releaseTime;

            plansByKey[childKey].push(
                YearlyPlan({
                    releaseTime: newPlans[i].releaseTime,
                    amount: newPlans[i].amount,
                    released: newPlans[i].released
                })
            );
            planIndexPlus1ByKey[childKey][newPlans[i].releaseTime] = plansByKey[childKey]
                .length;
        }

        emit PlansReplaced(childKey, newPlans.length);
    }

    // --------- Execute Vesting  ---------
    function doVesting(
        address token,
        address beneficiary,
        uint64 vestingId,
        uint64 vestingTime,
        uint256 amount
        // address destination <- 2026.01.30 audit으로 인해 제거 함, 검증 필요(프론트&백에서 테스트 해보지 못함)
    ) external nonReentrant {
        if (
            !(hasRole(SCHEDULER_ROLE, msg.sender) ||
                hasRole(ADMIN_ROLE, msg.sender))
        ) revert Unauthorized();

        bytes32 childKey = vestingKey(beneficiary, token, vestingId);
        Vesting storage v = vestingByKey[childKey];
        if (v.beneficiary == address(0)) revert InvalidParameters();
        if (!v.isActive) revert NotActive();

        uint64 nowTs = uint64(block.timestamp);
        if (vestingTime > nowTs) revert VestingNotReached();
        if (v.lastReleaseTime > nowTs) revert VestingNotReached();

        // destination 허용: beneficiary 또는 tokenInfo.mintWallet
        // address mintWallet = tokenInfoByToken[token].mintWalletAddress;
        // if (!(destination == beneficiary || destination == mintWallet))
        //     revert Unauthorized();
        address destination = v.destination;
        if (destination == address(0)) revert InvalidParameters();

        uint256 idxPlus1 = planIndexPlus1ByKey[childKey][vestingTime];
        if (idxPlus1 == 0) revert InvalidParameters();
        YearlyPlan storage p = plansByKey[childKey][idxPlus1 - 1];

        if (p.releaseTime != vestingTime) revert InvalidParameters();
        if (p.released) revert AlreadyReleased();
        if (p.amount != amount) revert InvalidParameters();
        if (p.releaseTime > nowTs) revert VestingNotReached();

        if (v.remainingReserved < amount) revert InsufficientAmount();
        if (v.releasedAmount + amount > v.totalAmount)
            revert InvalidParameters();

        // 토큰 전송
        IERC20(token).safeTransfer(destination, amount);

        // 상태 업데이트
        v.releasedAmount += amount;
        v.lastReleaseTime = nowTs;
        v.remainingReserved -= amount;
        globalReserved[token] -= amount;
        p.released = true;

        emit VestingExecuted(childKey, vestingTime, amount, destination);
    }

    // --------- Parent deduction helpers ---------
    function _deductFromParentPlans(
        bytes32 parentKey,
        YearlyPlanInput[] calldata childPlans
    ) internal {
        YearlyPlan[] storage parent = plansByKey[parentKey];
        if (parent.length == 0) revert InvalidParameters();

        uint64 childTge = childPlans.length > 0 ? childPlans[0].releaseTime : 0;
        uint64 parentTge = parent[0].releaseTime;
        bool tgeEqual = (childTge == parentTge);

        if (tgeEqual) {
            // 자식 플랜의 releaseTime과 같은 부모 플랜을 찾아 자식 amount만큼 차감
            for (uint256 i = 0; i < childPlans.length; i++) {
                if (childPlans[i].released) continue;

                uint256 idxPlus1 = planIndexPlus1ByKey[parentKey][
                    childPlans[i].releaseTime
                ];
                if (idxPlus1 == 0) revert InvalidParameters();

                YearlyPlan storage pp = parent[idxPlus1 - 1];
                if (pp.released) revert InvalidParameters();
                if (pp.amount < childPlans[i].amount)
                    revert InsufficientAmount();
                pp.amount -= childPlans[i].amount;
            }
        } else {
            // 자식의 첫 플랜이 부모의 첫 플랜과 시간이 다를 떄를 위한 규칙
            // 자식의 unreleased 플랜을 모은 뒤, TGE(인덱스 0)만 스킵
            uint256[] memory parentIdx = new uint256[](parent.length);
            uint256 c = 0;
            for (uint256 i = 0; i < parent.length; i++) {
                if (!parent[i].released) {
                    parentIdx[c] = i;
                    c++;
                }
            }
            // if (c < 2) revert InvalidParameters();

            // TGE가 unreleased면 parentIdex[0] == 0 이므로 1부터,
            // TGE가 이미 released면 0부터 시작해야 함
            uint256 start = parent[0].released ? 0 : 1;

            // child unreleased 개수 계산
            uint256 need = 0;
            for (uint256 i = 0; i < childPlans.length; i++) {
                if (!childPlans[i].released) need++;
            }

            if (c < start || c - start < need) revert InsufficientAmount();

            // uint256 parentPtr = 1; // skip 0
            uint256 parentPtr = start;
            for (uint256 i = 0; i < childPlans.length; i++) {
                if (childPlans[i].released) continue;
                // if (parentPtr >= c) revert InsufficientAmount();

                YearlyPlan storage pp = parent[parentIdx[parentPtr]];
                if (pp.amount < childPlans[i].amount)
                    revert InsufficientAmount();
                pp.amount -= childPlans[i].amount;
                parentPtr++;
            }
        }
    }

    function _returnToParentPlans(
        bytes32 parentKey,
        YearlyPlan[] storage childOldPlans
    ) internal {
        YearlyPlan[] storage parent = plansByKey[parentKey];
        if (parent.length == 0) revert InvalidParameters();

        uint64 childTge = childOldPlans.length > 0
            ? childOldPlans[0].releaseTime
            : 0;
        uint64 parentTge = parent[0].releaseTime;
        bool tgeEqual = (childTge == parentTge);

        if (tgeEqual) {
            for (uint256 i = 0; i < childOldPlans.length; i++) {
                if (childOldPlans[i].released) continue;

                uint256 idxPlus1 = planIndexPlus1ByKey[parentKey][
                    childOldPlans[i].releaseTime
                ];
                if (idxPlus1 == 0) revert InvalidParameters();

                YearlyPlan storage pp = parent[idxPlus1 - 1];
                // parent released 여부와 관계없이 amount만 복구
                pp.amount += childOldPlans[i].amount;
            }
        } else {
            uint256[] memory parentIdx = new uint256[](parent.length);
            uint256 c = 0;
            for (uint256 i = 0; i < parent.length; i++) {
                if (!parent[i].released) {
                    parentIdx[c] = i;
                    c++;
                }
            }
            // if (c < 2) revert InvalidParameters();

            uint256 start = parent[0].released ? 0 : 1;

            uint256 need = 0;
            for (uint256 i = 0; i < childOldPlans.length; i++) {
                if (!childOldPlans[i].released) need++;
            }

            if (c < start || c - start < need) revert InvalidParameters();

            // uint256 parentPtr = 1; // skip 0
            uint256 parentPtr = start;
            for (uint256 i = 0; i < childOldPlans.length; i++) {
                if (childOldPlans[i].released) continue;
                // if (parentPtr >= c) revert InvalidParameters();

                YearlyPlan storage pp = parent[parentIdx[parentPtr]];
                pp.amount += childOldPlans[i].amount;
                parentPtr++;
            }
        }
    }
    
    function _emitVestingCreated(bytes32 key) internal {
        Vesting storage v = vestingByKey[key];
        emit VestingCreated(key, v.beneficiary, v.token, v.vestingId, v.parentKey);
    }
}
