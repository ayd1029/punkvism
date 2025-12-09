use anchor_lang::prelude::*;
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("DcjmKSSKNxbSAwBQZx8wSAhosxBxQoyz3DdXuysMiPTy");

const CATEGORY_MAX_LEN: usize = 50;
const DISCRIMINATOR_SIZE: usize = 8;
const STRING_LENGTH_PREFIX: usize = 4; // String 길이 prefix (u32)

const VESTING_ACCOUNT_SPACE: usize = DISCRIMINATOR_SIZE
    + 32  // beneficiary (Pubkey)
    + 8   // total_amount
    + 8   // released_amount
    + 8   // start_time
    + 8   // end_time
    + 8   // last_release_time
    + 32  // token_mint (Pubkey)
    + 32  // token_vault (Pubkey)
    + 32  // beneficiary_vault (Pubkey)
    + STRING_LENGTH_PREFIX + CATEGORY_MAX_LEN  // category (String)
    + 1   // is_active (bool)
    + 32 // destination_token_account (Pubkey)
    + 32; // parent_vault

#[program]
pub mod vesting {
    use super::*;
    // deployer admin 설정
    pub fn initialize_deployer(ctx: Context<InitializeDeployer>) -> Result<()> {
        let deployer_admin = &mut ctx.accounts.deploy_admin;
        deployer_admin.deployer = ctx.accounts.deployer.key();
        Ok(())
    }

    // admin 계정 설정
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        require!(
            ctx.accounts.deployer_admin.deployer == ctx.accounts.deployer.key(),
            VestingError::NotDeployAdmin
        );
        let admin_config = &mut ctx.accounts.admin_config;
        admin_config.admin = ctx.accounts.admin.key();
        Ok(())
    }

    pub fn do_vesting(
        ctx: Context<DoVesting>,
        amount: u64,
        vesting_time: i64,
        params: VestingParams,
    ) -> Result<()> {
        let now = Clock::get()?;
        let vesting_account = &mut ctx.accounts.vesting_account;
        let admin = &ctx.accounts.admin;
        let admin_config = &ctx.accounts.admin_config;

        // msg!("vesting_account = {}", vesting_account.key());
        // msg!("beneficiary = {}", vesting_account.beneficiary.key());
        // msg!("token_mint = {}", vesting_account.token_mint.key());
        // msg!("params.vesting_id  = {}", params.vesting_id);
        // msg!("amount  = {}", amount);
        // msg!("vesting_time  = {}", vesting_time);

        require!(
            admin_config.admin == admin.key(),
            VestingError::Unauthorized
        );
        require!(vesting_account.is_active, VestingError::NotActive);
        require!(
            vesting_account.last_release_time <= now.unix_timestamp,
            VestingError::VestingNotReached
        );

        require!(
            vesting_time <= now.unix_timestamp,
            VestingError::VestingNotReached
        );
        // token_vault, parent_vault
        // origin_token_account PDA 검증
        let expected_origin_pda = Pubkey::find_program_address(
            &[
                b"vault",
                ctx.accounts.beneficiary.key.as_ref(),
                ctx.accounts.token_mint.key().as_ref(),
                &params.vesting_id.to_le_bytes(),
            ],
            ctx.program_id,
        ).0;

        require_keys_eq!(
            ctx.accounts.origin_token_account.key(),
            expected_origin_pda,
            VestingError::Unauthorized
        );

        // destination_token_address ATA 검증
        let expected_ata = get_associated_token_address(
            &ctx.accounts.beneficiary.key(),
            &ctx.accounts.token_mint.key(),
        );

        let admin_ata = get_associated_token_address(
            &ctx.accounts.token_info.mint_wallet_address,
            &ctx.accounts.token_mint.key(),
        );

        require_keys_eq!(
            ctx.accounts.destination_token_account.mint,
            ctx.accounts.token_mint.key(),
            VestingError::InvalidMint
        );

        let dest = &ctx.accounts.destination_token_account;
        let is_beneficiary_ata =
            dest.key() == expected_ata && dest.owner == ctx.accounts.beneficiary.key();
        let is_admin_ata =
            dest.key() == admin_ata && dest.owner == ctx.accounts.token_info.mint_wallet_address;

        require!(
            is_beneficiary_ata || is_admin_ata,
            VestingError::Unauthorized
        );

        // 백엔드에서 전달받은 vesting_account로
        // plan chunk의 seeds =  [b"plans", vesting_account.key().as_ref()] 를 통해 vesting_account에 해당하는 plan chunk 조회
        // 해당 planChunk의 plans 데이터 중 전달받은 vestingTime과 같은 plan 1개 조회
        // 해당 plan의 amount가 전달받은 amount와 동일한지 확인
        // 같으면 origin_token_account에서 destination_token_account로 amount만큼 전송

        let vesting_plan = &mut ctx.accounts.plan_chunk;
        let plan = &mut vesting_plan
            .plans
            .iter_mut()
            .find(|p| p.release_time == vesting_time)
            .ok_or(VestingError::InvalidParameters)?;

        require!(
            plan.release_time <= now.unix_timestamp,
            VestingError::VestingNotReached
        );
        require!(!plan.released, VestingError::AlreadyReleased);
        require!(plan.amount == amount, VestingError::InvalidParameters);

        let admin_key = ctx.accounts.admin.key();
        let token_vault_key = ctx.accounts.token_vault.key();

        let (_vault_authority_pda, bump) = Pubkey::find_program_address(
            &[b"vault_auth", admin_key.as_ref(), token_vault_key.as_ref()],
            ctx.program_id,
        );
        let seeds = &[
            b"vault_auth",
            admin_key.as_ref(),
            token_vault_key.as_ref(),
            &[bump],
        ];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.origin_token_account.to_account_info(),
                    to: ctx.accounts.destination_token_account.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )?;

        vesting_account.released_amount = vesting_account
            .released_amount
            .checked_add(amount)
            .ok_or(VestingError::Overflow)?;
        vesting_account.last_release_time = now.unix_timestamp;
        plan.released = true;

        Ok(())
    }

    pub fn lockup_vault(ctx: Context<LockupVault>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.admin_token_account.to_account_info(),
                    to: ctx.accounts.token_vault.to_account_info(),
                    authority: ctx.accounts.admin.to_account_info(),
                },
            ),
            amount,
        )?;
        Ok(())
    }

    pub fn create_vesting(ctx: Context<CreateVesting>, params: VestingParams) -> Result<()> {
        let _vesting_account_info = ctx.accounts.vesting_account.to_account_info();
        let vesting_account = &mut ctx.accounts.vesting_account;
        let _clock = Clock::get()?;

        // admin인지 검사
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        require!(
            ctx.accounts.token_info.token_mint == ctx.accounts.token_mint.key(),
            VestingError::InvalidToken
        );

        // 파라미터 유효성 검사
        require!(params.total_amount > 0, VestingError::InvalidParameters);

        require!(
            ctx.accounts.beneficiary_vault.key() != ctx.accounts.parent_vault.key(),
            VestingError::InvalidParameters
        );

        let amount_to_transfer = params
            .total_amount
            .checked_sub(params.released_amount)
            .ok_or(VestingError::InvalidParameters)?;

        vesting_account.beneficiary = ctx.accounts.beneficiary.key(); // 토큰 수령 주소
        vesting_account.total_amount = params.total_amount; // 전체 베스팅 토큰 수량
        vesting_account.released_amount = params.released_amount; // 언락 토큰 수량
        vesting_account.start_time = params.start_time; // 베스팅 시작 시간 설정
                                                        // vesting_account.cliff_time = params.cliff_time; // release 가능 시간
        vesting_account.end_time = params.end_time; // 베스팅 완료 시간 설정
        vesting_account.token_mint = ctx.accounts.token_mint.key(); // 베스팅 토큰 주소
        vesting_account.token_vault = ctx.accounts.token_vault.key(); // 베스팅 볼트 주소
        vesting_account.beneficiary_vault = ctx.accounts.beneficiary_vault.key();

        vesting_account.destination_token_account = ctx.accounts.beneficiary_token_account.key(); // 수정할 토큰 수령 주소
        vesting_account.category = params.category.clone(); // 팀, 마케팅 등 카테고리 정보
        vesting_account.is_active = true; // 베스팅 활성 및 비활성 여부
        vesting_account.parent_vault = ctx.accounts.parent_vault.key();

        let admin_key = ctx.accounts.admin.key();
        let token_vault_key = ctx.accounts.token_vault.key();

        let (_vault_auth, vault_auth_bump) = Pubkey::find_program_address(
            &[b"vault_auth", admin_key.as_ref(), token_vault_key.as_ref()],
            ctx.program_id,
        );

        let signer_seeds: &[&[u8]; 4] = &[
            b"vault_auth",
            admin_key.as_ref(),
            token_vault_key.as_ref(),
            &[vault_auth_bump],
        ];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.parent_vault.to_account_info(),
                    to: ctx.accounts.beneficiary_vault.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                &[signer_seeds],
            ),
            amount_to_transfer,
        )?;

        Ok(())
    }

    pub fn user_create_vesting(
        ctx: Context<UserCreateVesting>,
        params: VestingParams,
    ) -> Result<()> {
        let vesting_account = &mut ctx.accounts.vesting_account;
        let _clock = Clock::get()?;

        // admin인지 검사
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        require!(
            ctx.accounts.token_info.token_mint == ctx.accounts.token_mint.key(),
            VestingError::InvalidToken
        );

        require!(
            ctx.accounts.beneficiary_vault.key() != ctx.accounts.parent_vault.key(),
            VestingError::InvalidParameters
        );

        let plans = &mut ctx.accounts.parent_plan_chunk.plans;
        require!(!plans.is_empty(), VestingError::ParentPlanNotFound);

        let amount_to_transfer = params
            .total_amount
            .checked_sub(params.released_amount)
            .ok_or(VestingError::InvalidParameters)?;

        vesting_account.beneficiary = ctx.accounts.beneficiary.key(); // 토큰 수령 주소
        vesting_account.total_amount = params.total_amount; // 전체 베스팅 토큰 수량
        vesting_account.released_amount = params.released_amount; // 언락 토큰 수량
        vesting_account.start_time = params.start_time; // 베스팅 시작 시간 설정
                                                        // vesting_account.cliff_time = params.cliff_time; // release 가능 시간
        vesting_account.end_time = params.end_time; // 베스팅 완료 시간 설정
        vesting_account.token_mint = ctx.accounts.token_mint.key(); // 베스팅 토큰 주소
        vesting_account.token_vault = ctx.accounts.token_vault.key(); // 베스팅 볼트 주소
        vesting_account.beneficiary_vault = ctx.accounts.beneficiary_vault.key();

        vesting_account.destination_token_account = ctx.accounts.beneficiary_token_account.key(); // 수정할 토큰 수령 주소
        vesting_account.category = params.category.clone(); // 팀, 마케팅 등 카테고리 정보
        vesting_account.is_active = true; // 베스팅 활성 및 비활성 여부
        vesting_account.parent_vault = ctx.accounts.parent_vault.key();

        let admin_key = ctx.accounts.admin.key();
        let token_vault_key = ctx.accounts.token_vault.key();

        let (_vault_auth, vault_auth_bump) = Pubkey::find_program_address(
            &[b"vault_auth", admin_key.as_ref(), token_vault_key.as_ref()],
            ctx.program_id,
        );

        let signer_seeds: &[&[u8]; 4] = &[
            b"vault_auth",
            admin_key.as_ref(),
            token_vault_key.as_ref(),
            &[vault_auth_bump],
        ];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.parent_vault.to_account_info(),
                    to: ctx.accounts.beneficiary_vault.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                &[signer_seeds],
            ),
            amount_to_transfer,
        )?;

        Ok(())
    }

    pub fn append_yearly_plan(
        ctx: Context<AppendYearlyPlan>,
        plans: Vec<YearlyPlan>,
    ) -> Result<()> {
        require!(
            ctx.accounts.admin_config.admin == ctx.accounts.admin.key(),
            VestingError::Unauthorized
        );

        // 입력 plans 검증
        require!(!plans.is_empty(), VestingError::InvalidParameters);
        require!(plans.len() <= 52, VestingError::InvalidParameters); // 최대 52개월(약 4.3년) 제한
        
        let now = Clock::get()?.unix_timestamp;
        let max_future_time = now.checked_add(10 * 365 * 24 * 60 * 60).ok_or(VestingError::InvalidParameters)?; // 10년 후까지
        
        // plans의 총합 검증을 위한 변수
        let mut total_plan_amount: u64 = 0;
        
        for plan in &plans {
            require!(plan.amount > 0, VestingError::InvalidParameters);
            require!(plan.release_time > 0, VestingError::InvalidParameters);
            // release_time이 합리적인 범위 내인지 확인 (과거가 아니고, 너무 먼 미래가 아닌지)
            // now는 i64, plan.release_time도 i64이므로 타입 일치
            require!(
                plan.release_time >= now.saturating_sub(86400), // 최대 1일 전까지 허용 (시간대 차이 고려)
                VestingError::InvalidParameters
            );
            require!(
                plan.release_time <= max_future_time,
                VestingError::InvalidParameters
            );
            // 총합 계산 (오버플로우 체크)
            total_plan_amount = total_plan_amount
                .checked_add(plan.amount)
                .ok_or(VestingError::Overflow)?;
        }

        // release_time이 엄격하게 증가하는지 확인 (필수: parent/child 매칭을 위해)
        // >= 와 != 를 결합하여 > (엄격한 증가)로 통합
        for i in 1..plans.len() {
            require!(
                plans[i].release_time > plans[i - 1].release_time,
                VestingError::InvalidParameters
            );
        }

        let chunk = &mut ctx.accounts.plan_chunk;
        let deduct = ctx.accounts.vesting_account.token_vault.key()
            != ctx.accounts.vesting_account.parent_vault.key();

        if deduct {
            // parent_plan_chunk가 제공된 경우 parent_vesting_account도 필수
            let parent_vesting_account = ctx
                .accounts
                .parent_vesting_account
                .as_ref()
                .ok_or(VestingError::ParentPlanNotFound)?;

            // immutable borrow를 블록으로 제한하여 검증 후 drop
            {
                let parent_chunk_ref = ctx
                    .accounts
                    .parent_plan_chunk
                    .as_ref()
                    .ok_or(VestingError::ParentPlanNotFound)?;

                // 해당 프로그램 소유인지 확인
                let ai = parent_chunk_ref.to_account_info();
                require!(ai.owner == ctx.program_id, VestingError::Unauthorized);

                // parent_plan_chunk.vesting_account가 parent_vesting_account와 일치하는지 검증
                require_keys_eq!(
                    parent_chunk_ref.vesting_account,
                    parent_vesting_account.key(),
                    VestingError::InvalidParameters
                );

                // parent_plan_chunk가 올바른 PDA인지 검증 (seeds: [b"plans", parent_vesting_account.key()])
                let expected_parent_plan_chunk = Pubkey::find_program_address(
                    &[b"plans", parent_vesting_account.key().as_ref()],
                    ctx.program_id,
                ).0;
                require_keys_eq!(
                    parent_chunk_ref.key(),
                    expected_parent_plan_chunk,
                    VestingError::InvalidParameters
                );

                // parent_plan_chunk가 비어있지 않은지 확인
                require!(!parent_chunk_ref.plans.is_empty(), VestingError::ParentPlanNotFound);
            } // parent_chunk_ref 여기서 drop

            // 이제 mutable borrow (immutable 참조가 drop된 후)
            let parent_chunk = ctx
                .accounts
                .parent_plan_chunk
                .as_deref_mut()
                .ok_or(VestingError::ParentPlanNotFound)?;

            // parent plans의 구조적 검증
            for i in 0..parent_chunk.plans.len() {
                // 각 parent plan의 amount가 0보다 큰지 확인
                require!(
                    parent_chunk.plans[i].amount > 0,
                    VestingError::InvalidParameters
                );
                // release_time이 유효한지 확인
                require!(
                    parent_chunk.plans[i].release_time > 0,
                    VestingError::InvalidParameters
                );
            }

            // parent plans의 release_time도 엄격하게 증가하는지 확인
            for i in 1..parent_chunk.plans.len() {
                require!(
                    parent_chunk.plans[i].release_time > parent_chunk.plans[i - 1].release_time,
                    VestingError::InvalidParameters
                );
            }
            
            // vesting_account와 parent_vesting_account 간의 명확한 부모-자식 관계 검증
            // vesting_account.parent_vault는 다음 중 하나와 일치해야 함:
            // 1. parent_vesting_account.token_vault (최상위에서 직접 받는 경우)
            // 2. parent_vesting_account.beneficiary_vault (하위에서 받는 경우)
            let is_valid_parent_vault = 
                ctx.accounts.vesting_account.parent_vault == parent_vesting_account.token_vault ||
                ctx.accounts.vesting_account.parent_vault == parent_vesting_account.beneficiary_vault;
            require!(
                is_valid_parent_vault,
                VestingError::InvalidParameters
            );
            
            // vesting_account와 parent_vesting_account가 같은 token_mint를 사용하는지 확인
            require_keys_eq!(
                ctx.accounts.vesting_account.token_mint,
                parent_vesting_account.token_mint,
                VestingError::InvalidParameters
            );

            // parent plans에서 사용 가능한 총량 계산 (unreleased plans의 합)
            let parent_available_amount: u64 = parent_chunk
                .plans
                .iter()
                .filter(|p| !p.released)
                .map(|p| p.amount)
                .try_fold(0u64, |acc, amount| acc.checked_add(amount))
                .ok_or(VestingError::Overflow)?;
            
            // plans의 총합이 parent에서 사용 가능한 양을 초과하지 않는지 사전 검증
            // (실제 차감은 매칭 로직에서 수행하지만, 사전 검증으로 명확한 오류 메시지 제공)
            let user_unreleased_total: u64 = plans
                .iter()
                .filter(|p| !p.released)
                .map(|p| p.amount)
                .try_fold(0u64, |acc, amount| acc.checked_add(amount))
                .ok_or(VestingError::Overflow)?;
            
            // TGE가 같을 때는 정확히 매칭되므로, user_unreleased_total이 parent_available_amount를 초과하면 안됨
            // TGE가 다를 때는 skip(1) 로직이므로 더 복잡하지만, 최소한 parent에 충분한 양이 있는지 확인
            let user_tge_time = plans.first().map(|p| p.release_time);
            let parent_tge_time = parent_chunk.plans.first().map(|p| p.release_time);
            let tge_equal = user_tge_time == parent_tge_time;

            if tge_equal {
                // TGE가 같을 때: user_unreleased_total이 parent_available_amount를 초과하면 안됨
                require!(
                    user_unreleased_total <= parent_available_amount,
                    VestingError::InsufficientAmount
                );
                // TGE 같으면 release_time으로 정확히 매칭
                // 입력 plans는 모두 released=false로 검증되었으므로 released 체크 불필요
                for user_plan in &plans {
                    // 같은 release_time을 가진 parent_plan 찾기 (released=false인 것만)
                    let parent_plan = parent_chunk
                        .plans
                        .iter_mut()
                        .find(|p| p.release_time == user_plan.release_time && !p.released)
                        .ok_or(VestingError::InvalidParameters)?;

                    require!(
                        parent_plan.amount >= user_plan.amount,
                        VestingError::InsufficientAmount
                    );

                    parent_plan.amount = parent_plan
                        .amount
                        .checked_sub(user_plan.amount)
                        .ok_or(VestingError::Overflow)?;
                }
                // TGE equal 케이스는 전체 적용
                chunk.plans.extend(plans);
            } else {
                // TGE 다르면: user false[0]부터, parent false[1]부터 매칭해서 차감
                // 입력 plans는 모두 released=false로 검증되었으므로 필터링 불필요하지만 안전성을 위해 유지
                let user_unreleased: Vec<&YearlyPlan> =
                    plans.iter().filter(|p| !p.released).collect();
                
                // parent의 released == false 플랜의 인덱스만 저장 (Rust borrow 규칙 준수)
                let parent_unreleased_indices: Vec<usize> = parent_chunk
                    .plans
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| !p.released)
                    .map(|(i, _)| i)
                    .collect();

                // parent_unreleased가 최소 2개 이상 있어야 함 (skip(1)을 위해)
                require!(
                    parent_unreleased_indices.len() >= 2,
                    VestingError::InvalidParameters
                );
                
                // TGE가 다를 때: skip(1) 후 사용 가능한 parent amount 계산
                let parent_available_after_skip: u64 = parent_unreleased_indices
                    .iter()
                    .skip(1) // 첫 번째는 건너뛰기
                    .map(|&idx| parent_chunk.plans[idx].amount)
                    .try_fold(0u64, |acc, amount| acc.checked_add(amount))
                    .ok_or(VestingError::Overflow)?;
                
                // user_unreleased_total이 skip(1) 후 사용 가능한 양을 초과하면 안됨
                require!(
                    user_unreleased_total <= parent_available_after_skip,
                    VestingError::InsufficientAmount
                );

                // 유저 0부터, 재단 1부터 1:1 대응 (정렬된 순서 보장됨)
                // 부분 적용을 위한 안전한 처리
                let mut applied = 0usize;
                let mut parent_idx_iter = parent_unreleased_indices.iter().skip(1);

                for user_plan in user_unreleased.iter() {
                    if let Some(&parent_idx) = parent_idx_iter.next() {
                        let parent_plan = &mut parent_chunk.plans[parent_idx];
                        
                        // 재단 amount가 부족한 경우 차감 불가 → 더 이상 진행하지 않음
                        if parent_plan.amount < user_plan.amount {
                            break;
                        }
                        
                        // 차감 처리
                        parent_plan.amount = parent_plan
                            .amount
                            .checked_sub(user_plan.amount)
                            .ok_or(VestingError::Overflow)?;
                        
                        applied += 1;
                    } else {
                        // parent 플랜 부족
                        break;
                    }
                }

                // applied 개수만 chunk에 추가 (부분 적용)
                if applied > 0 {
                    let partial: Vec<YearlyPlan> = plans.iter()
                        .take(applied)
                        .cloned()
                        .collect();
                    chunk.plans.extend(partial);
                }
                // applied == 0이면 아무것도 추가하지 않음
            }
        } else {
            // deduct == false (top-level vesting)인 경우 전체 적용
            chunk.plans.extend(plans);
        }

        // chunk.vesting_account는 한 번만 설정
        chunk.vesting_account = ctx.accounts.vesting_account.key();
        Ok(())
    }

    pub fn update_plan_chunk(ctx: Context<UpdatePlanChunk>, plans: Vec<YearlyPlan>) -> Result<()> {
        let plan_chunk = &mut ctx.accounts.plan_chunk;

        plan_chunk.plans.clear();
        plan_chunk.plans.extend(plans);

        Ok(())
    }

    // 긴급 정지 함수 (is_active 상태 변경)
    pub fn emergency_stop(ctx: Context<EmergencyStop>) -> Result<()> {
        let vesting_account = &mut ctx.accounts.vesting_account;
        vesting_account.is_active = !vesting_account.is_active; // 토글 기능

        Ok(())
    }

    pub fn close_vesting_account(_ctx: Context<CloseVestingAccount>) -> Result<()> {
        Ok(())
    }

    pub fn remove_admin(ctx: Context<RemoveAdmin>) -> Result<()> {
        require!(
            ctx.accounts.deployer_admin.deployer == ctx.accounts.deployer.key(),
            VestingError::NotDeployAdmin
        );

        Ok(())
    }

    pub fn init_token_info(ctx: Context<InitTokenInfo>, args: TokenInfoArgs) -> Result<()> {
        require!(
            ctx.accounts.admin_config.admin == ctx.accounts.scheduler_admin.key(),
            VestingError::Unauthorized
        );

        let token_info = &mut ctx.accounts.token_info;

        token_info.token_name = args.token_name;
        token_info.token_symbol = args.token_symbol;
        token_info.total_supply = args.total_supply;
        token_info.token_mint = args.token_mint;
        token_info.mint_wallet_address = args.mint_wallet_address;

        Ok(())
    }

}

// 베스팅 정보 저장
#[account]
pub struct VestingAccount {
    pub beneficiary: Pubkey,
    pub total_amount: u64,
    pub released_amount: u64,
    pub start_time: i64,
    pub end_time: i64,
    pub last_release_time: i64,
    pub token_mint: Pubkey,
    pub token_vault: Pubkey,
    pub beneficiary_vault: Pubkey,
    pub category: String,
    pub is_active: bool,
    pub destination_token_account: Pubkey,
    pub parent_vault: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct YearlyPlan {
    pub release_time: i64,
    pub amount: u64,
    pub released: bool,
}

#[account]
pub struct VestingPlanChunk {
    pub vesting_account: Pubkey,
    pub plans: Vec<YearlyPlan>,
}

// admin 정보를 저장할 계정
#[account]
pub struct AdminConfig {
    pub admin: Pubkey,
}

#[account]
pub struct DeployAdmin {
    pub deployer: Pubkey,
}

#[derive(Accounts)]
pub struct InitializeDeployer<'info> {
    #[account(mut)]
    pub deployer: Signer<'info>, // 배포자 = signer

    #[account(
        init,
        payer = deployer,
        space = 8 + 32, // discriminator + pubkey
        seeds = [b"deploy_admin"],
        bump
    )]
    pub deploy_admin: Account<'info, DeployAdmin>,

    pub system_program: Program<'info, System>,
}

// 프로그램 초기화 시 admin 설정을 위한 구조체
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub deployer: Signer<'info>,

    #[account(
        seeds = [b"deploy_admin"],
        bump
    )]
    pub deployer_admin: Account<'info, DeployAdmin>,

    // 스케줄러 주소
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + 32, // discriminator + pubkey
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount: u64, vesting_time: i64, params: VestingParams)]
pub struct DoVesting<'info> {
    // 스케줄러 관리자
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(mut)]
    pub token_vault: Account<'info, TokenAccount>,

    /// CHECK: token_vault의 authority로 사용되는 PDA (seeds: [b"vault_auth", admin.key, token_vault.key])
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub origin_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub destination_token_account: Account<'info, TokenAccount>,

    // #[account(
    //     init_if_needed,
    //     payer = admin,
    //     space = VESTING_ACCOUNT_SPACE,
    //     seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
    //     bump
    // )]
    // pub vesting_account: Account<'info, VestingAccount>,
    #[account(mut)]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        mut,
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Box<Account<'info, TokenInfo>>,

    /// CHECK: 수혜자
    pub beneficiary: AccountInfo<'info>,
    pub token_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct LockupVault<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(mut)]
    pub admin_token_account: Account<'info, TokenAccount>,
    pub token_mint: Account<'info, Mint>,

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,
        seeds = [b"vault", admin_config.admin.as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_vault: Account<'info, TokenAccount>,

    /// CHECK: vault authority PDA 
    #[account(
        seeds = [b"vault_auth", admin_config.admin.as_ref(), token_vault.key().as_ref()],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

// 베스팅 생성
#[derive(Accounts)]
#[instruction(params: VestingParams)]
pub struct CreateVesting<'info> {
    // 스케줄러 주소
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, // admin 계정 검사
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Box<Account<'info, TokenInfo>>,

    /// CHECK: 수혜자
    pub beneficiary: AccountInfo<'info>,

    #[account(
        init,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub vesting_account: Account<'info, VestingAccount>,

    pub token_mint: Account<'info, Mint>,

    // 토큰 민팅 지갑 주소 + 민트 주소
    #[account(mut)]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    // 2차 지갑에게 토큰을 전송할 1차 지갑 vault
    #[account(mut)]
    pub parent_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,
        seeds = [b"vault", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,

    /// CHECK: token_vault의 새로운 authority로 사용하는 PDA
    #[account(
        seeds = [b"vault_auth", admin.key().as_ref(), token_vault.key().as_ref()],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,
    // 1차 지갑의 경우 -> 메인 vault -> transfer 시 메인 vault에서 beneficiary_vault(1차 지갑)으로 전송
    #[account(mut)]
    pub beneficiary_token_account: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(params: VestingParams)]
pub struct UserCreateVesting<'info> {
    // 스케줄러 주소
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, // admin 계정 검사
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Box<Account<'info, TokenInfo>>,

    /// CHECK: 수혜자
    pub beneficiary: AccountInfo<'info>,

    #[account(
        init,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub vesting_account: Box<Account<'info, VestingAccount>>,

    pub token_mint: Account<'info, Mint>,

    // 토큰 민팅 지갑 주소 + 민트 주소
    #[account(mut)]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    // 2차 지갑에게 토큰을 전송할 1차 지갑 vault
    #[account(mut)]
    pub parent_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,
        seeds = [b"vault", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,

    /// CHECK: token_vault의 새로운 authority로 사용하는 PDA
    #[account(
        seeds = [b"vault_auth", admin.key().as_ref(), token_vault.key().as_ref()],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,
    // 1차 지갑의 경우 -> 메인 vault -> transfer 시 메인 vault에서 beneficiary_vault(1차 지갑)으로 전송
    #[account(mut)]
    pub beneficiary_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub parent_vesting_account: Box<Account<'info, VestingAccount>>,

    #[account(
        mut,
        seeds = [b"plans", parent_vesting_account.key().as_ref()],
        bump
    )]
    pub parent_plan_chunk: Box<Account<'info, VestingPlanChunk>>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct AppendYearlyPlan<'info> {
    #[account(mut)]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + 32 + 4 + (52 * (8 + 8 + 1)),
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    /// CHECK: parent plan chunk - must be PDA derived from parent_vesting_account if provided
    #[account(mut)]
    pub parent_plan_chunk: Option<Account<'info, VestingPlanChunk>>,

    /// CHECK: parent vesting account for validation
    pub parent_vesting_account: Option<Account<'info, VestingAccount>>,

    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, 
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePlanChunk<'info> {
    #[account(mut)]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, 
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,
}

#[derive(Accounts)]
pub struct EmergencyStop<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// CHECK: beneficiary account
    pub beneficiary: AccountInfo<'info>,

    pub token_mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = vesting_account.beneficiary == beneficiary.key() @ VestingError::Unauthorized,
        constraint = vesting_account.token_mint == token_mint.key() @ VestingError::Unauthorized
    )]
    pub vesting_account: Account<'info, VestingAccount>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VestingParams {
    pub vesting_id: u64,
    pub total_amount: u64,
    pub released_amount: u64,
    pub start_time: i64,
    pub end_time: i64,
    pub category: String,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VestingInfo {
    pub total_amount: u64,
    pub released_amount: u64,
    pub releasable_amount: u64,
    pub next_release_time: i64,
    pub is_active: bool,
}

// PDA 렌트비 반환
#[derive(Accounts)]
pub struct CloseVestingAccount<'info> {
    // 스케줄러 어드민
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(mut, close = admin)]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        mut,
        close = admin,
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(
        constraint = beneficiary_vault.key() == vesting_account.beneficiary_vault @ VestingError::Unauthorized,
        constraint = beneficiary_vault.amount == 0 @ VestingError::VaultNotEmpty,
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveAdmin<'info> {
    #[account(mut)]
    pub deployer: Signer<'info>,

    #[account(
        seeds = [b"deploy_admin"],
        bump
    )]
    pub deployer_admin: Account<'info, DeployAdmin>,

    #[account(mut)]
    /// CHECK: admin 계정으로, 소유자 권한 확인 등은 코드에서 직접 처리함
    pub admin: AccountInfo<'info>,

    #[account(
        mut,
        close = deployer,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,
}

#[account]
pub struct TokenInfo {
    pub token_name: String,
    pub token_symbol: String,
    pub total_supply: u64,
    pub token_mint: Pubkey,
    pub mint_wallet_address: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct TokenInfoArgs {
    pub token_name: String,
    pub token_symbol: String,
    pub total_supply: u64,
    pub token_mint: Pubkey,
    pub mint_wallet_address: Pubkey,
}

#[derive(Accounts)]
pub struct InitTokenInfo<'info> {
    #[account(mut)]
    pub scheduler_admin: Signer<'info>,

    #[account(
        init,
        payer = scheduler_admin,
        space = 8 + 4 + 32 + 4 + 10 + 8 + 32 + 32,
        seeds = [b"token_info", scheduler_admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Account<'info, TokenInfo>,

    #[account(
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub token_mint: Account<'info, Mint>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum VestingError {
    #[msg("Veseting period has not ended yet")]
    VestingNotReached,
    #[msg("No tokens available for release")]
    NoTokensToRelease,
    #[msg("Unauthorized operation")]
    Unauthorized,
    #[msg("Vesting is not active")]
    NotActive,
    #[msg("Invalid vesting parameters")]
    InvalidParameters,
    #[msg("Add amount is overflow")]
    Overflow,
    #[msg("You are not the deployer admin.")]
    NotDeployAdmin,
    #[msg("No parent vesting plan found.")]
    ParentPlanNotFound,
    #[msg("Insufficient amount in the parent vesting plan.")]
    InsufficientAmount,
    #[msg("Vesting for the specified time has already been completed.")]
    AlreadyReleased,
    #[msg("Token not registered in token_info.")]
    InvalidToken,
    #[msg("Vault must be empty before closing the vesting account.")]
    VaultNotEmpty,
    #[msg("Invalid Mint")]
    InvalidMint,
}
