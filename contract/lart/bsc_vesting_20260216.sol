// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract VestingProgram is ReentrancyGuard {
    using SafeERC20 for IERC20;

    /* ========== ERRORS (Anchor VestingError 대응) ========== */
    error VestingNotReached();
    error Unauthorized();
    error NotActive();
    error InvalidParameters();
    error Overflow();
    error NotDeployAdmin();
    error ParentPlanNotFound();
    error InsufficientAmount();
    error AlreadyReleased();
    error InvalidToken();
    error VaultNotEmpty();
    error InvalidMint();
    error SlotAlreadyOccupied();

    /* ========== STRUCTS ========== */

    struct YearlyPlan {
        int64 releaseTime;
        uint256 amount;
        bool released;
    }

    struct VestingAccount {
        address beneficiary;
        uint256 totalAmount;
        uint256 releasedAmount;
        int64 startTime;
        int64 endTime;
        int64 lastReleaseTime;
        address tokenMint;
        address destinationTokenAccount;
        string category;
        bool isActive;
        bytes32 vaultId;       // Anchor PDA 대응
        bytes32 parentVaultId; // Anchor parent_vault 대응
    }

    struct TokenInfo {
        string tokenName;
        string tokenSymbol;
        uint256 totalSupply;
        address tokenMint;
        address mintWalletAddress;
    }
	
    struct VestingParams {
        uint256 vestingId;
        address parentBeneficiary;
        uint256 parentVestingId;
        uint256 totalAmount;
        uint256 releasedAmount;
        int64 startTime;
        int64 endTime;
        string category;
        address tokenMint;
        address destinationTokenAccount;
    }

    /* ========== STATE ========== */

    address public deployer;
    address public admin;

    // beneficiary => vestingId => VestingAccount
    mapping(address => mapping(uint256 => VestingAccount)) public vestings;

    // beneficiary => vestingId => plans
    mapping(address => mapping(uint256 => YearlyPlan[])) public plans;

    // admin => tokenMint => TokenInfo
    mapping(address => mapping(address => TokenInfo)) public tokenInfos;

    // vaultId => allocated amount (Anchor vault balance 개념)
    mapping(bytes32 => uint256) public vaultAllocated;
	
    // ===== INDEXING STORAGE (VIEW ) =====

    // beneficiary => vestingIds[]
    mapping(address => uint256[]) public beneficiaryVestingIds;

    // tokenMint => beneficiaries[]
    mapping(address => address[]) public tokenBeneficiaries;

    // tokenMint => beneficiary => already added?
    mapping(address => mapping(address => bool)) public tokenBeneficiaryAdded;
    
    /* ========== event ========== */
    event BeneficiaryMigrated(
        address indexed oldBeneficiary,
        address indexed newBeneficiary,
        uint256 indexed vestingId
    );
    /* ========== INIT ========== */

    constructor() {
        deployer = msg.sender;
    }

    function initialize(address _admin) external {
        if (msg.sender != deployer) revert NotDeployAdmin();
        admin = _admin;
    }

    /* ========== INTERNAL HELPERS ========== */

    function _vaultId(
        address beneficiary,
        address tokenMint,
        uint256 vestingId
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("vault", beneficiary, tokenMint, vestingId)
        );
    }

    /* ========== TOKEN LOCKUP (Anchor lockup_vault) ========== */

    function lockupVault(address token, uint256 amount) external nonReentrant {
        if (msg.sender != admin) revert Unauthorized();
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    }

    /* ========== CREATE VESTING (Anchor create_vesting) ========== */

    function createVesting(
        address beneficiary,
        uint256 vestingId,
        uint256 totalAmount,
        uint256 releasedAmount,
        int64 startTime,
        int64 endTime,
        string calldata category,
        address tokenMint,
        bytes32 parentVaultId,
        address destinationTokenAccount
    ) external nonReentrant {
        if (msg.sender != admin) revert Unauthorized();
        if (totalAmount == 0) revert InvalidParameters();
        if (vestings[beneficiary][vestingId].beneficiary != address(0))
            revert InvalidParameters();
		if (releasedAmount > totalAmount) revert InvalidParameters();

        bytes32 vaultId = _vaultId(beneficiary, tokenMint, vestingId);

        uint256 alloc = totalAmount - releasedAmount;
        vaultAllocated[vaultId] += alloc;

        vestings[beneficiary][vestingId] = VestingAccount({
            beneficiary: beneficiary,
            totalAmount: totalAmount,
            releasedAmount: releasedAmount,
            startTime: startTime,
            endTime: endTime,
            lastReleaseTime: 0,
            tokenMint: tokenMint,
            destinationTokenAccount: destinationTokenAccount,
            category: category,
            isActive: true,
            vaultId: vaultId,
            parentVaultId: parentVaultId
        });
		 // INDEXING (조회용 )
		beneficiaryVestingIds[beneficiary].push(vestingId);

		if (!tokenBeneficiaryAdded[tokenMint][beneficiary]) {
			tokenBeneficiaries[tokenMint].push(beneficiary);
			tokenBeneficiaryAdded[tokenMint][beneficiary] = true;
		}
    }

    /* ========== DO VESTING (Anchor do_vesting) ========== */

    function doVesting(
        address beneficiary,
        uint256 vestingId,
        uint256 amount,
        int64 vestingTime
    ) external nonReentrant {
        if (msg.sender != admin) revert Unauthorized();

        VestingAccount storage v = vestings[beneficiary][vestingId];
        if (!v.isActive) revert NotActive();
        if (vestingTime > int64(uint64(block.timestamp)))
            revert VestingNotReached();

        YearlyPlan[] storage p = plans[beneficiary][vestingId];

        bool found;
        for (uint256 i = 0; i < p.length; i++) {
            if (p[i].releaseTime == vestingTime) {
                if (p[i].released) revert AlreadyReleased();
                if (p[i].amount != amount) revert InvalidParameters();
                p[i].released = true;
                found = true;
                break;
            }
        }
        if (!found) revert InvalidParameters();

        if (v.releasedAmount + amount > v.totalAmount) revert Overflow();
        if (vaultAllocated[v.vaultId] < amount)
            revert InsufficientAmount();

        vaultAllocated[v.vaultId] -= amount;
        v.releasedAmount += amount;
        v.lastReleaseTime = int64(uint64(block.timestamp));

        IERC20(v.tokenMint).safeTransfer(
            v.destinationTokenAccount,
            amount
        );
    }

    /* ========== APPEND YEARLY PLAN (Anchor append_yearly_plan) ========== */

    function appendYearlyPlan(
        address beneficiary,
        uint256 vestingId,
        address parentBeneficiary,
        uint256 parentVestingId,
        YearlyPlan[] calldata newPlans
    ) external {
        if (msg.sender != admin) revert Unauthorized();
        if (newPlans.length == 0) revert InvalidParameters();

        if (parentBeneficiary != address(0)) {
            YearlyPlan[] storage parentPlans =
                plans[parentBeneficiary][parentVestingId];
            if (parentPlans.length == 0) revert ParentPlanNotFound();

            bool tgeEqual =
                newPlans[0].releaseTime == parentPlans[0].releaseTime;

            if (tgeEqual) {
                for (
                    uint256 i = 0;
                    i < newPlans.length && i < parentPlans.length;
                    i++
                ) {
                    if (!newPlans[i].released && !parentPlans[i].released) {
                        if (parentPlans[i].amount < newPlans[i].amount)
                            revert InsufficientAmount();
                        parentPlans[i].amount -= newPlans[i].amount;
                    }
                }
            } else {
                uint256 parentIdx = 1;
                for (uint256 i = 0; i < newPlans.length; i++) {
                    if (!newPlans[i].released) {
                        while (
                            parentIdx < parentPlans.length &&
                            parentPlans[parentIdx].released
                        ) parentIdx++;

                        if (parentIdx < parentPlans.length) {
                            if (
                                parentPlans[parentIdx].amount <
                                newPlans[i].amount
                            ) revert InsufficientAmount();
                            parentPlans[parentIdx].amount -= newPlans[i].amount;
                            parentIdx++;
                        }
                    }
                }
            }
        }

        for (uint256 i = 0; i < newPlans.length; i++) {
            plans[beneficiary][vestingId].push(newPlans[i]);
        }
    }

    /* ========== EMERGENCY STOP (Anchor toggle) ========== */

    function emergencyStop(
        address beneficiary,
        uint256 vestingId
    ) external {
        if (msg.sender != admin) revert Unauthorized();
        vestings[beneficiary][vestingId].isActive =
            !vestings[beneficiary][vestingId].isActive;
    }

    /* ========== TOKEN INFO ========== */

    function initTokenInfo(
        address tokenMint,
        TokenInfo calldata info
    ) external {
        if (msg.sender != admin) revert Unauthorized();
        tokenInfos[admin][tokenMint] = info;
    }
	
	function userCreateVesting(
		address beneficiary,
		VestingParams calldata params
	) external nonReentrant {
		if (msg.sender != admin) revert Unauthorized();
		if (params.releasedAmount > params.totalAmount) revert InvalidParameters();

		// 1. 부모 플랜 존재
		if (plans[params.parentBeneficiary][params.parentVestingId].length == 0)
			revert ParentPlanNotFound();

		// 2. 중복 방지
		if (vestings[beneficiary][params.vestingId].beneficiary != address(0))
			revert InvalidParameters();

		VestingAccount storage parent =
			vestings[params.parentBeneficiary][params.parentVestingId];

		// 3. mint 일관성
		if (parent.tokenMint != params.tokenMint) revert InvalidMint();

		bytes32 vId = _vaultId(beneficiary, params.tokenMint, params.vestingId);
		bytes32 pVId = parent.vaultId;

		// 4. 부모 vault 검증
		if (pVId == bytes32(0)) revert InvalidParameters();

		uint256 amountToTransfer = params.totalAmount - params.releasedAmount;

		// 5. 부모 vault에서 차감
		if (vaultAllocated[pVId] < amountToTransfer) revert InsufficientAmount();

		vaultAllocated[pVId] -= amountToTransfer;
		vaultAllocated[vId] += amountToTransfer;

		// 6. struct memory로 먼저 만들고 mapping에 저장
		VestingAccount memory newVesting = VestingAccount({
			beneficiary: beneficiary,
			totalAmount: params.totalAmount,
			releasedAmount: params.releasedAmount,
			startTime: params.startTime,
			endTime: params.endTime,
			lastReleaseTime: 0,
			tokenMint: params.tokenMint,
			destinationTokenAccount: params.destinationTokenAccount,
			category: params.category,
			isActive: true,
			vaultId: vId,
			parentVaultId: pVId
		});

		vestings[beneficiary][params.vestingId] = newVesting;

		// 7. indexing
		beneficiaryVestingIds[beneficiary].push(params.vestingId);

		if (!tokenBeneficiaryAdded[params.tokenMint][beneficiary]) {
			tokenBeneficiaries[params.tokenMint].push(beneficiary);
			tokenBeneficiaryAdded[params.tokenMint][beneficiary] = true;
		}
	}

	function closeVestingAccount(
		address beneficiary,
		uint256 vestingId
	) external {
		if (msg.sender != admin) revert Unauthorized();

		VestingAccount storage v = vestings[beneficiary][vestingId];
		if (v.beneficiary == address(0)) revert InvalidParameters();

		// Anchor: vault must be empty
		if (vaultAllocated[v.vaultId] > 0) revert VaultNotEmpty();

		// Anchor semantics: inactive or finished
		if (v.isActive) revert NotActive();

		delete plans[beneficiary][vestingId];
		delete vestings[beneficiary][vestingId];
	}
	/* ========== INTEGRATED VIEW FUNCTION (With Token Info) ========== */

    /**
     * @notice 특정 지갑/ID의 베스팅 상세 정보, 플랜 리스트, 그리고 관련 토큰의 메타데이터를 함께 조회합니다.
     * @return account 베스팅 계정 상세 정보 (안에 tokenMint 포함)
     * @return allPlans 전체 베스팅 스케줄 리스트
     * @return tokenMeta 관리자가 등록한 토큰의 이름, 심볼 등 정보
     * @return amounts [총 물량, 해제된 물량, 남은 물량] 배열 (가독성을 위해 배열로 묶음)
     */
    function getFullVestingInfoWithToken(address beneficiary, uint256 vestingId)
        external
        view
        returns (
            VestingAccount memory account,
            YearlyPlan[] memory allPlans,
            TokenInfo memory tokenMeta,
            uint256[3] memory amounts // [total, released, remaining]
        )
    {
        account = vestings[beneficiary][vestingId];
        allPlans = plans[beneficiary][vestingId];
        
        // 해당 베스팅에 설정된 토큰 주소로 토큰 정보 조회
        tokenMeta = tokenInfos[admin][account.tokenMint];
        
        amounts[0] = account.totalAmount;
        amounts[1] = account.releasedAmount;
        amounts[2] = amounts[0] > amounts[1] ? amounts[0] - amounts[1] : 0;
    }
	
	function getTokenVestingSummariesPaged(
		address tokenMint,
		uint256 offset,
		uint256 limit
	)
		external
		view
		returns (
			address[] memory beneficiaries,
			uint256[][] memory vIds,
			uint256[3][][] memory stats
		)
	{
		address[] storage allBs = tokenBeneficiaries[tokenMint];
		uint256 totalAvailable = allBs.length;

		if (offset >= totalAvailable) {
			return (new address[](0), new uint256[][](0), new uint256[3][][](0));
		}

		uint256 end = (offset + limit > totalAvailable) ? totalAvailable : offset + limit;
		uint256 count = end - offset;

		beneficiaries = new address[](count);
		vIds = new uint256[][](count);
		stats = new uint256[3][][](count);

		for (uint256 i = 0; i < count; i++) {
			address user = allBs[offset + i];
			beneficiaries[i] = user;
			
			// 데이터 추출 로직을 별도 함수로 위임하여 스택 부하를 줄임
			_getUserVestingData(tokenMint, user, i, vIds, stats);
		}
	}

	/**
	 * @dev 특정 사용자의 베스팅 데이터를 추출하여 결과 배열에 기록 (Stack too deep 방지용)
	 */
	function _getUserVestingData(
		address tokenMint,
		address user,
		uint256 index,
		uint256[][] memory vIds,
		uint256[3][][] memory stats
	) internal view {
		uint256[] storage ids = beneficiaryVestingIds[user];
		
		// 1. matchCount 계산
		uint256 matchCount = 0;
		for (uint256 j = 0; j < ids.length; j++) {
			if (vestings[user][ids[j]].tokenMint == tokenMint) {
				matchCount++;
			}
		}

		vIds[index] = new uint256[](matchCount);
		stats[index] = new uint256[3][](matchCount);

		// 2. 데이터 채우기
		uint256 k = 0;
		for (uint256 j = 0; j < ids.length; j++) {
			uint256 vId = ids[j];
			VestingAccount storage v = vestings[user][vId]; // storage로 참조하여 가스비와 스택 절약
			
			if (v.tokenMint == tokenMint) {
				vIds[index][k] = vId;
				stats[index][k][0] = v.totalAmount;
				stats[index][k][1] = v.releasedAmount;
				stats[index][k][2] = v.totalAmount > v.releasedAmount 
					? v.totalAmount - v.releasedAmount 
					: 0;
				k++;
			}
		}
	}

	
	/**
	 * @notice 기존의 베스팅 플랜을 모두 삭제하고 새로운 플랜 리스트로 교체합니다.
	 * @dev Anchor의 update_plan_chunk와 동일한 기능을 수행합니다.
	 */
	function updatePlanChunk(
		address beneficiary,
		uint256 vestingId,
		YearlyPlan[] calldata newPlans
	) external {
		if (msg.sender != admin) revert Unauthorized();
		if (newPlans.length == 0) revert InvalidParameters();
		
		// 1. 해당 베스팅 계정이 존재하는지 확인
		if (vestings[beneficiary][vestingId].beneficiary == address(0)) 
			revert InvalidParameters();

		// 2. 기존 플랜 리스트 삭제 (Anchor의 .clear()와 동일)
		delete plans[beneficiary][vestingId];

		// 3. 새로운 플랜들 추가 (Anchor의 .extend()와 동일)
		for (uint256 i = 0; i < newPlans.length; i++) {
			plans[beneficiary][vestingId].push(newPlans[i]);
		}
	}
	
	function _removeVestingId(address user, uint256 vestingId) internal {
		uint256[] storage ids = beneficiaryVestingIds[user];

		for (uint256 i = 0; i < ids.length; i++) {
			if (ids[i] == vestingId) {
				ids[i] = ids[ids.length - 1];
				ids.pop();
				break;
			}
		}
	}

	function migrateBeneficiary(
		address oldBeneficiary,
		address newBeneficiary,
		uint256 vestingId,
		address newDestinationTokenAccount
	) external nonReentrant {
		if (msg.sender != deployer) revert Unauthorized(); // 관리자 권한 체크 추가
		require(oldBeneficiary != newBeneficiary, "same");
		require(newBeneficiary != address(0), "zero");

		VestingAccount storage v = vestings[oldBeneficiary][vestingId];
		require(v.beneficiary == oldBeneficiary, "not owner");
		require(v.isActive, "not active"); // 활성화 상태 체크 권장

		// 0. Overwrite 방지 (중요: 새 슬롯이 비었는지 확인)
		if (vestings[newBeneficiary][vestingId].beneficiary != address(0)) {
			revert SlotAlreadyOccupied();
		}

		// 1. Vault 이동
		bytes32 oldVaultId = v.vaultId;
		bytes32 newVaultId = _vaultId(newBeneficiary, v.tokenMint, vestingId);

		uint256 remainingAlloc = vaultAllocated[oldVaultId];
		vaultAllocated[newVaultId] = remainingAlloc;
		delete vaultAllocated[oldVaultId];

		// 2. Storage Copy (Vesting Account)
		vestings[newBeneficiary][vestingId] = v;
		
		// 3. Plans 데이터 복사 (이 부분이 반드시 필요합니다!)
		plans[newBeneficiary][vestingId] = plans[oldBeneficiary][vestingId];

		// 4. 필드 업데이트
		VestingAccount storage nv = vestings[newBeneficiary][vestingId];
		nv.beneficiary = newBeneficiary;
		nv.destinationTokenAccount = newDestinationTokenAccount;
		nv.vaultId = newVaultId;

		// 5. 인덱싱 및 정리
		_removeVestingId(oldBeneficiary, vestingId);
		beneficiaryVestingIds[newBeneficiary].push(vestingId);

		// 토큰별 수혜자 명단 업데이트 (기존 코드의 로직 유지)
		if (!tokenBeneficiaryAdded[v.tokenMint][newBeneficiary]) {
			tokenBeneficiaries[v.tokenMint].push(newBeneficiary);
			tokenBeneficiaryAdded[v.tokenMint][newBeneficiary] = true;
		}

		// 6. 원본 삭제
		delete vestings[oldBeneficiary][vestingId];
		delete plans[oldBeneficiary][vestingId];

		emit BeneficiaryMigrated(oldBeneficiary, newBeneficiary, vestingId);
	}

	
}
