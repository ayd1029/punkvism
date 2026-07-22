use anchor_lang::prelude::*;                          // Anchor basic prelude: Import accounts, macros, and types
use anchor_spl::associated_token::get_associated_token_address; // SPL ATA utility: Function for calculating ATA
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer}; // Types/functions used for SPL Token CPI

declare_id!("DcjmKSSKNxbSAwBQZx8wSAhosxBxQoyz3DdXuysMiPTy"); // Declare program ID (on-chain program id)

const CATEGORY_MAX_LEN: usize = 50;                   // Maximum length for the category string
const DISCRIMINATOR_SIZE: usize = 8;                  // Anchor account discriminator (8 bytes)
const STRING_LENGTH_PREFIX: usize = 4; // String length prefix (u32) - Anchor prepends this during String serialization
const MAX_PLANS: usize = 52;                          // Maximum number of yearly plans in a chunk
const TOKEN_NAME_MAX_LEN: usize = 32;                 // Maximum length for the token name string
const TOKEN_SYMBOL_MAX_LEN: usize = 10;               // Maximum length for the token symbol string

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
    + 32; // parent_vault - calculate total account space

#[program]
pub mod vesting {                                      // Start of the Anchor program module
    use super::*;                                     // Use symbols from the parent scope
    // Set deployer admin
    pub fn initialize_deployer(ctx: Context<InitializeDeployer>) -> Result<()> { // Register deployer
        let deployer_admin = &mut ctx.accounts.deploy_admin; // Get a handle to the PDA account
        deployer_admin.deployer = ctx.accounts.deployer.key(); // Record the deployer's Pubkey
        Ok(())
    }

    // Set admin account
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> { // Deployer designates an admin
        require!(
            ctx.accounts.deployer_admin.deployer == ctx.accounts.deployer.key(), // Is the caller the registered deployer?
            VestingError::NotDeployAdmin
        );
        let admin_config = &mut ctx.accounts.admin_config; // Reference to the AdminConfig PDA
        admin_config.admin = ctx.accounts.admin.key();      // Designate as admin
        Ok(())
    }

    pub fn do_vesting(
        ctx: Context<DoVesting>,
        amount: u64,                                      // Amount to be released
        vesting_time: i64,                                // Release time
        params: VestingParams,                            // Additional parameters like vesting_id
    ) -> Result<()> {
        let now = Clock::get()?;                          // Current on-chain time
        let vesting_account = &mut ctx.accounts.vesting_account; // Target vesting account
        let admin = &ctx.accounts.admin;                   // Admin account (signer)
        let admin_config = &ctx.accounts.admin_config;     // Admin configuration

        // Debug logs commented out
        // msg!("vesting_account = {}", vesting_account.key());
        // ...

        require!(
            admin_config.admin == admin.key(),            // Does the call signer match the registered admin?
            VestingError::Unauthorized
        );
        require!(vesting_account.is_active, VestingError::NotActive); // Is the vesting active?
        require!(
            vesting_account.last_release_time <= now.unix_timestamp,  // Has time passed since the last release?
            VestingError::VestingNotReached
        );

        // Validate account relationships to prevent data corruption
        require_keys_eq!(
            vesting_account.beneficiary,
            ctx.accounts.beneficiary.key(),
            VestingError::Unauthorized
        );
        require_keys_eq!(
            vesting_account.token_mint,
            ctx.accounts.token_mint.key(),
            VestingError::InvalidMint
        );
        require_keys_eq!(
            ctx.accounts.plan_chunk.vesting_account,
            vesting_account.key(),
            VestingError::InvalidParameters
        );

        require!(
            vesting_time <= now.unix_timestamp,           // Is the requested release time in the past or present?
            VestingError::VestingNotReached
        );
        // token_vault, parent_vault
        // Verify origin_token_account PDA
        let expected_origin_pda = Pubkey::find_program_address( // Calculate the expected source Vault PDA
            &[
                b"vault",                                     // Fixed seed
                ctx.accounts.beneficiary.key.as_ref(),         // Beneficiary key
                ctx.accounts.token_mint.key().as_ref(),        // Token Mint
                &params.vesting_id.to_le_bytes(),              // vesting id
            ],
            ctx.program_id,
        ).0;                                                   // Use only the PDA (pubkey)

        require_keys_eq!(
            ctx.accounts.origin_token_account.key(),           // The actual origin vault passed in
            expected_origin_pda,                               // Must be the same as what we calculated
            VestingError::Unauthorized
        );

        // Verify destination_token_address ATA
        let expected_ata = get_associated_token_address(       // Standard ATA for the beneficiary
            &ctx.accounts.beneficiary.key(),
            &ctx.accounts.token_mint.key(),
        );

        let admin_ata = get_associated_token_address(          // ATA of the token minting wallet
            &ctx.accounts.token_info.mint_wallet_address,
            &ctx.accounts.token_mint.key(),
        );

        require_keys_eq!(
            ctx.accounts.destination_token_account.mint,       // The destination account's mint must match
            ctx.accounts.token_mint.key(),
            VestingError::InvalidMint
        );

        let dest = &ctx.accounts.destination_token_account;    // Destination token account
        let is_beneficiary_ata =
            dest.key() == expected_ata && dest.owner == ctx.accounts.beneficiary.key(); // Is it the beneficiary's ATA?
        let is_admin_ata =
            dest.key() == admin_ata && dest.owner == ctx.accounts.token_info.mint_wallet_address; // Is it the admin's (mint wallet) ATA?

        require!(
            is_beneficiary_ata || is_admin_ata,                // Must be one of the two to be allowed
            VestingError::Unauthorized
        );

        // The backend finds the plan chunk corresponding to the vesting_account, and among them, finds the plan where release_time == vesting_time
        let vesting_plan = &mut ctx.accounts.plan_chunk;       // Collection of plans for this vesting (PDA)
        require!(
            !vesting_plan.plans.is_empty(),
            VestingError::InvalidParameters
        );
        assert_vesting_plan_cap(
            vesting_account.total_amount,
            vesting_account.released_amount,
            &vesting_plan.plans,
        )?;
        let mut matching_plan: Vec<&mut YearlyPlan> = vesting_plan
            .plans
            .iter_mut()
            .filter(|p| p.release_time == vesting_time)
            .collect();
        let plan = match (matching_plan.pop(), matching_plan.pop()) {
            (Some(plan), None) => Ok(plan),
            _ => Err(VestingError::InvalidParentPlan),
        }?;

        require!(
            plan.release_time <= now.unix_timestamp,           // Has the time for that plan passed?
            VestingError::VestingNotReached
        );
        require!(!plan.released, VestingError::AlreadyReleased); // Cannot proceed if the plan has already been released
        require!(plan.amount == amount, VestingError::InvalidParameters); // The requested amount must match the plan's amount

        // vesting cap: 누적 해지금이 total_amount를 초과하지 않도록 강제
        let next_released = vesting_account
            .released_amount
            .checked_add(amount)
            .ok_or(VestingError::Overflow)?;
        require!(
            next_released <= vesting_account.total_amount,
            VestingError::InsufficientAmount
        );

        let admin_key = ctx.accounts.admin.key();              // Cache the admin key
        let token_vault_key = ctx.accounts.token_vault.key();  // Token vault key

        let (_vault_authority_pda, bump) = Pubkey::find_program_address( // Calculate the vault authority PDA
            &[b"vault_auth", admin_key.as_ref(), token_vault_key.as_ref()],
            ctx.program_id,
        );
        let seeds = &[
            b"vault_auth",                                    // Authority PDA seeds
            admin_key.as_ref(),
            token_vault_key.as_ref(),
            &[bump],
        ];

        token::transfer(                                       // SPL Token transfer CPI
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),  // Token program
                Transfer {
                    from: ctx.accounts.origin_token_account.to_account_info(), // Source
                    to: ctx.accounts.destination_token_account.to_account_info(), // Destination
                    authority: ctx.accounts.vault_authority.to_account_info(), // Authority (PDA)
                },
                &[seeds],                                      // Sign with PDA signer
            ),
            amount,                                            // Transfer amount
        )?;

        vesting_account.released_amount = vesting_account       // Update cumulative released amount
            .released_amount
            .checked_add(amount)
            .ok_or(VestingError::Overflow)?;
        vesting_account.last_release_time = now.unix_timestamp; // Update last release time
        plan.released = true;                                   // Mark this plan as completed

        Ok(())
    }

    pub fn lockup_vault(ctx: Context<LockupVault>, amount: u64) -> Result<()> {
        // register-before-deposit: 미등록 mint는 vault에 넣을 수 없음
        require!(
            ctx.accounts.token_info.token_mint == ctx.accounts.token_mint.key(),
            VestingError::InvalidToken
        );
        require!(amount > 0, VestingError::InvalidParameters);

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

    pub fn create_vesting(
        ctx: Context<CreateVesting>,
        params: VestingParams,
        plans: Vec<YearlyPlan>,
    ) -> Result<()> {
        // Create vesting account + install schedule atomically
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        require!(
            ctx.accounts.token_info.token_mint == ctx.accounts.token_mint.key(),
            VestingError::InvalidToken
        );

        require!(params.total_amount > 0, VestingError::InvalidParameters);
        require!(
            params.released_amount <= params.total_amount,
            VestingError::InvalidParameters
        );

        require!(
            ctx.accounts.beneficiary_vault.key() != ctx.accounts.parent_vault.key(),
            VestingError::InvalidParameters
        );

        let amount_to_transfer = params
            .total_amount
            .checked_sub(params.released_amount)
            .ok_or(VestingError::InvalidParameters)?;

        // 펀딩과 스케줄을 한 트랜잭션에서 묶기 위해 초기 plan을 필수·완전하게 검증
        validate_and_measure_initial_plans(&plans, amount_to_transfer, params.released_amount)?;

        let vesting_key = ctx.accounts.vesting_account.key();
        {
            let vesting_account = &mut ctx.accounts.vesting_account;
            vesting_account.beneficiary = ctx.accounts.beneficiary.key();
            vesting_account.total_amount = params.total_amount;
            vesting_account.released_amount = params.released_amount;
            vesting_account.start_time = params.start_time;
            vesting_account.end_time = params.end_time;
            vesting_account.token_mint = ctx.accounts.token_mint.key();
            vesting_account.token_vault = ctx.accounts.token_vault.key();
            vesting_account.beneficiary_vault = ctx.accounts.beneficiary_vault.key();
            vesting_account.destination_token_account =
                ctx.accounts.beneficiary_token_account.key();
            vesting_account.category = params.category.clone();
            vesting_account.is_active = true;
            vesting_account.parent_vault = ctx.accounts.parent_vault.key();
        }

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

        let chunk = &mut ctx.accounts.plan_chunk;
        chunk.vesting_account = vesting_key;
        chunk.plans.clear();
        chunk.plans.extend(plans);

        assert_vesting_plan_cap(
            params.total_amount,
            params.released_amount,
            &chunk.plans,
        )?;

        Ok(())
    }

    pub fn user_create_vesting(
        ctx: Context<UserCreateVesting>,
        params: VestingParams,
        plans: Vec<YearlyPlan>,
    ) -> Result<()> {
        // Create child vesting + schedule + parent deduction atomically
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

        require!(params.total_amount > 0, VestingError::InvalidParameters);
        require!(
            params.released_amount <= params.total_amount,
            VestingError::InvalidParameters
        );

        require!(
            !ctx.accounts.parent_plan_chunk.plans.is_empty(),
            VestingError::InvalidParentPlan
        );

        let amount_to_transfer = params
            .total_amount
            .checked_sub(params.released_amount)
            .ok_or(VestingError::InvalidParameters)?;

        validate_and_measure_initial_plans(&plans, amount_to_transfer, params.released_amount)?;

        // parent 스케줄 차감을 토큰 이동/child plan 설치와 원자적으로 수행
        take_from_parent_plan(&mut ctx.accounts.parent_plan_chunk, &plans)?;

        let vesting_key = ctx.accounts.vesting_account.key();
        {
            let vesting_account = &mut ctx.accounts.vesting_account;
            vesting_account.beneficiary = ctx.accounts.beneficiary.key();
            vesting_account.total_amount = params.total_amount;
            vesting_account.released_amount = params.released_amount;
            vesting_account.start_time = params.start_time;
            vesting_account.end_time = params.end_time;
            vesting_account.token_mint = ctx.accounts.token_mint.key();
            vesting_account.token_vault = ctx.accounts.token_vault.key();
            vesting_account.beneficiary_vault = ctx.accounts.beneficiary_vault.key();
            vesting_account.destination_token_account =
                ctx.accounts.beneficiary_token_account.key();
            vesting_account.category = params.category.clone();
            vesting_account.is_active = true;
            vesting_account.parent_vault = ctx.accounts.parent_vault.key();
        }

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

        let chunk = &mut ctx.accounts.plan_chunk;
        chunk.vesting_account = vesting_key;
        chunk.plans.clear();
        chunk.plans.extend(plans);

        assert_vesting_plan_cap(
            params.total_amount,
            params.released_amount,
            &chunk.plans,
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

        require!(!plans.is_empty(), VestingError::InvalidParameters);
        require!(plans.len() <= MAX_PLANS, VestingError::InvalidParameters);

        // append는 미해지 스케줄만 추가 (부분 적용/중복 release_time 방지)
        validate_yearly_plans(&plans, true)?;

        let chunk = &mut ctx.accounts.plan_chunk;
        require!(
            chunk.plans.len() + plans.len() <= MAX_PLANS,
            VestingError::InsufficientSpace
        );

        // 기존 chunk와 합쳐도 release_time 중복이 없고 엄격 증가하도록 보장
        ensure_no_duplicate_release_times(&chunk.plans, &plans)?;

        let deduct = ctx.accounts.vesting_account.token_vault.key()
            != ctx.accounts.vesting_account.parent_vault.key();

        if deduct {
            // parent_plan_chunk가 제공된 경우 parent_vesting_account도 필수
            let parent_vesting_account = ctx
                .accounts
                .parent_vesting_account
                .as_ref()
                .ok_or(VestingError::InvalidParentPlan)?;

            // immutable borrow를 블록으로 제한하여 검증 후 drop
            {
                let parent_chunk_ref = ctx
                    .accounts
                    .parent_plan_chunk
                    .as_ref()
                    .ok_or(VestingError::InvalidParentPlan)?;

                assert_parent_chunk_binding(
                    ctx.program_id,
                    &ctx.accounts.vesting_account,
                    parent_vesting_account,
                    parent_chunk_ref,
                )?;
            } // parent_chunk_ref 여기서 drop

            // 이제 mutable borrow (immutable 참조가 drop된 후)
            let parent_chunk = ctx
                .accounts
                .parent_plan_chunk
                .as_deref_mut()
                .ok_or(VestingError::InvalidParentPlan)?;

            // parent plans: 차감으로 amount가 0일 수 있으므로 release_time 유일성만 강제
            validate_release_times_unique(&parent_chunk.plans)?;

            // parent plans에서 사용 가능한 총량 계산 (unreleased plans의 합)
            let parent_available_amount: u64 = parent_chunk
                .plans
                .iter()
                .filter(|p| !p.released)
                .map(|p| p.amount)
                .try_fold(0u64, |acc, amount| acc.checked_add(amount))
                .ok_or(VestingError::Overflow)?;

            let user_unreleased_total: u64 = plans
                .iter()
                .map(|p| p.amount)
                .try_fold(0u64, |acc, amount| acc.checked_add(amount))
                .ok_or(VestingError::Overflow)?;

            let user_tge_time = plans.first().map(|p| p.release_time);
            let parent_tge_time = parent_chunk.plans.first().map(|p| p.release_time);
            let tge_equal = user_tge_time == parent_tge_time;

            if tge_equal {
                require!(
                    user_unreleased_total <= parent_available_amount,
                    VestingError::InsufficientAmount
                );
                // TGE 같으면 release_time으로 정확히 매칭
                for user_plan in &plans {
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
            } else {
                // TGE 다르면: user[0]부터, parent unreleased[1]부터 1:1 매칭 차감
                let parent_unreleased_indices: Vec<usize> = parent_chunk
                    .plans
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| !p.released)
                    .map(|(i, _)| i)
                    .collect();

                require!(
                    parent_unreleased_indices.len() >= 2,
                    VestingError::InvalidParameters
                );

                let parent_available_after_skip: u64 = parent_unreleased_indices
                    .iter()
                    .skip(1)
                    .map(|&idx| parent_chunk.plans[idx].amount)
                    .try_fold(0u64, |acc, amount| acc.checked_add(amount))
                    .ok_or(VestingError::Overflow)?;

                require!(
                    user_unreleased_total <= parent_available_after_skip,
                    VestingError::InsufficientAmount
                );

                // parent 슬롯이 user plan보다 적으면 전체 revert (부분 적용 금지)
                require!(
                    parent_unreleased_indices.len().saturating_sub(1) >= plans.len(),
                    VestingError::InsufficientAmount
                );

                let mut parent_idx_iter = parent_unreleased_indices.iter().skip(1);
                for user_plan in &plans {
                    let parent_idx = *parent_idx_iter
                        .next()
                        .ok_or(VestingError::InsufficientAmount)?;
                    let parent_plan = &mut parent_chunk.plans[parent_idx];

                    require!(
                        parent_plan.amount >= user_plan.amount,
                        VestingError::InsufficientAmount
                    );

                    parent_plan.amount = parent_plan
                        .amount
                        .checked_sub(user_plan.amount)
                        .ok_or(VestingError::Overflow)?;
                }
            }

            chunk.plans.extend(plans);
        } else {
            // deduct == false (top-level vesting)인 경우 전체 적용
            chunk.plans.extend(plans);
        }

        // plan 합계가 vesting cap(total_amount / released_amount)을 넘지 않는지 검증
        assert_vesting_plan_cap(
            ctx.accounts.vesting_account.total_amount,
            ctx.accounts.vesting_account.released_amount,
            &chunk.plans,
        )?;

        // chunk.vesting_account는 한 번만 설정
        chunk.vesting_account = ctx.accounts.vesting_account.key();
        Ok(())
    }

    pub fn update_plan_chunk(ctx: Context<UpdatePlanChunk>, plans: Vec<YearlyPlan>) -> Result<()> {
        // Replace all plans
        require!(
            ctx.accounts.admin_config.admin == ctx.accounts.admin.key(),
            VestingError::Unauthorized
        );

        require!(plans.len() <= MAX_PLANS, VestingError::InsufficientSpace);
        // update는 이미 해지된 과거 plan을 포함할 수 있으므로 시간 윈도우 제약은 생략하되,
        // amount/release_time 유일성(엄격 증가) 및 released 불변성을 강제한다.
        if !plans.is_empty() {
            validate_yearly_plans(&plans, false)?;
        }

        let old_unreleased = sum_unreleased_amount(&ctx.accounts.plan_chunk.plans)?;
        let new_unreleased = sum_unreleased_amount(&plans)?;

        // 이미 해지된 tranche의 released 플래그/amount/release_time 변경·삭제 금지
        ensure_released_plans_immutable(&ctx.accounts.plan_chunk.plans, &plans)?;

        let is_user_vesting_account = ctx.accounts.vesting_account.token_vault
            != ctx.accounts.vesting_account.parent_vault;

        if is_user_vesting_account {
            let parent_vesting_account = ctx
                .accounts
                .parent_vesting_account
                .as_ref()
                .ok_or(VestingError::InvalidParentPlan)?;

            {
                let parent_chunk_ref = ctx
                    .accounts
                    .parent_plan_chunk
                    .as_ref()
                    .ok_or(VestingError::InvalidParentPlan)?;

                assert_parent_chunk_binding(
                    ctx.program_id,
                    &ctx.accounts.vesting_account,
                    parent_vesting_account,
                    parent_chunk_ref,
                )?;
            }

            let parent_plan_chunk = ctx
                .accounts
                .parent_plan_chunk
                .as_mut()
                .ok_or(VestingError::InvalidParentPlan)?;

            return_to_parent_plan(parent_plan_chunk, &ctx.accounts.plan_chunk.plans)?;
            take_from_parent_plan(parent_plan_chunk, &plans)?;
        }

        // 미해지 스케줄 합계 변화분만큼 parent <-> child vault 토큰을 함께 이동
        // (플랜만 바꾸고 vault balance가 남는/부족한 불일치 방지)
        if new_unreleased != old_unreleased {
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

            if new_unreleased > old_unreleased {
                let delta = new_unreleased
                    .checked_sub(old_unreleased)
                    .ok_or(VestingError::Overflow)?;
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
                    delta,
                )?;
                ctx.accounts.vesting_account.total_amount = ctx
                    .accounts
                    .vesting_account
                    .total_amount
                    .checked_add(delta)
                    .ok_or(VestingError::Overflow)?;
            } else {
                let delta = old_unreleased
                    .checked_sub(new_unreleased)
                    .ok_or(VestingError::Overflow)?;
                token::transfer(
                    CpiContext::new_with_signer(
                        ctx.accounts.token_program.to_account_info(),
                        Transfer {
                            from: ctx.accounts.beneficiary_vault.to_account_info(),
                            to: ctx.accounts.parent_vault.to_account_info(),
                            authority: ctx.accounts.vault_authority.to_account_info(),
                        },
                        &[signer_seeds],
                    ),
                    delta,
                )?;
                ctx.accounts.vesting_account.total_amount = ctx
                    .accounts
                    .vesting_account
                    .total_amount
                    .checked_sub(delta)
                    .ok_or(VestingError::Overflow)?;
            }
        }

        let chunk = &mut ctx.accounts.plan_chunk;
        chunk.plans.clear();
        chunk.plans.extend(plans);

        assert_vesting_plan_cap(
            ctx.accounts.vesting_account.total_amount,
            ctx.accounts.vesting_account.released_amount,
            &chunk.plans,
        )?;

        Ok(())
    }

    // Emergency stop function (change is_active state)
    pub fn emergency_stop(ctx: Context<EmergencyStop>) -> Result<()> { // Toggle between active/inactive
        let vesting_account = &mut ctx.accounts.vesting_account;
        vesting_account.is_active = !vesting_account.is_active;        // Toggle

        Ok(())
    }

    pub fn close_vesting_account(ctx: Context<CloseVestingAccount>) -> Result<()> {
        // funded vault는 이미 amount==0 constraint. 미해지 스케줄이 남아있으면 close 금지.
        require!(
            sum_unreleased_amount(&ctx.accounts.plan_chunk.plans)? == 0,
            VestingError::InvalidParameters
        );
        Ok(())
    }

    pub fn remove_admin(ctx: Context<RemoveAdmin>) -> Result<()> {    // Remove admin (deployer only)
        require!(
            ctx.accounts.deployer_admin.deployer == ctx.accounts.deployer.key(), // Check deployer
            VestingError::NotDeployAdmin
        );

        Ok(())                                                         // Actual close is handled in Accounts
    }

    pub fn init_token_info(ctx: Context<InitTokenInfo>, args: TokenInfoArgs) -> Result<()> { // Register token metadata
        require!(
            ctx.accounts.admin_config.admin == ctx.accounts.scheduler_admin.key(), // Is scheduler an admin?
            VestingError::Unauthorized
        );
        require!(args.token_name.len() <= TOKEN_NAME_MAX_LEN, VestingError::InvalidParameters);
        require!(args.token_symbol.len() <= TOKEN_SYMBOL_MAX_LEN, VestingError::InvalidParameters);

        let mint_authority = ctx.accounts.token_mint.mint_authority.ok_or(VestingError::InvalidMint)?;
        require!(mint_authority == args.mint_wallet_address, VestingError::Unauthorized);
        
        let token_info = &mut ctx.accounts.token_info;                 // TokenInfo PDA

        token_info.token_name = args.token_name;                       // Set name/symbol/total supply/mint/minting wallet
        token_info.token_symbol = args.token_symbol;
        token_info.total_supply = args.total_supply;
        token_info.token_mint = ctx.accounts.token_mint.key();
        token_info.mint_wallet_address = args.mint_wallet_address;

        Ok(())
    }
}

/// Plan 구조 검증.
/// - `enforce_time_window == true`: append용 (미해지, 가까운 과거~10년 이내)
/// - `enforce_time_window == false`: update용 (과거 released plan 허용, 중복만 금지)
fn validate_yearly_plans(plans: &[YearlyPlan], enforce_time_window: bool) -> Result<()> {
    require!(!plans.is_empty(), VestingError::InvalidParameters);

    let (now, max_future_time) = if enforce_time_window {
        let now = Clock::get()?.unix_timestamp;
        let max_future_time = now
            .checked_add(10 * 365 * 24 * 60 * 60)
            .ok_or(VestingError::InvalidParameters)?;
        (Some(now), Some(max_future_time))
    } else {
        (None, None)
    };

    for plan in plans {
        require!(plan.amount > 0, VestingError::InvalidParameters);
        require!(plan.release_time > 0, VestingError::InvalidParameters);

        if enforce_time_window {
            require!(!plan.released, VestingError::InvalidParameters);
            let now = now.ok_or(VestingError::InvalidParameters)?;
            let max_future_time = max_future_time.ok_or(VestingError::InvalidParameters)?;
            require!(
                plan.release_time >= now.saturating_sub(86400),
                VestingError::InvalidParameters
            );
            require!(
                plan.release_time <= max_future_time,
                VestingError::InvalidParameters
            );
        }
    }

    validate_release_times_unique(plans)
}

/// release_time > 0 및 엄격 증가(중복 불가)
fn validate_release_times_unique(plans: &[YearlyPlan]) -> Result<()> {
    require!(!plans.is_empty(), VestingError::InvalidParameters);
    for plan in plans {
        require!(plan.release_time > 0, VestingError::InvalidParameters);
    }
    for i in 1..plans.len() {
        require!(
            plans[i].release_time > plans[i - 1].release_time,
            VestingError::InvalidParameters
        );
    }
    Ok(())
}

/// 기존 chunk와 신규 plans를 합쳐도 release_time이 유일하고 엄격 증가하는지 확인
fn ensure_no_duplicate_release_times(
    existing: &[YearlyPlan],
    incoming: &[YearlyPlan],
) -> Result<()> {
    if existing.is_empty() {
        return Ok(());
    }

    // 기존 chunk 자체도 엄격 증가여야 함 (손상/구버전 데이터 방어)
    validate_release_times_unique(existing)?;

    // append는 스케줄 연장: 신규 첫 release_time이 기존 마지막보다 커야 함
    // (이 조건으로 기존 값과의 중복도 함께 차단)
    let last_existing = existing
        .last()
        .ok_or(VestingError::InvalidParameters)?
        .release_time;
    let first_incoming = incoming
        .first()
        .ok_or(VestingError::InvalidParameters)?
        .release_time;
    require!(
        first_incoming > last_existing,
        VestingError::InvalidParameters
    );

    Ok(())
}

/// 이미 해지된 plan은 update로 released=false 리셋/amount 변경/삭제할 수 없다.
/// 또한 기존에 해지되지 않은 tranche를 released=true로 위조하는 것도 금지한다.
fn ensure_released_plans_immutable(
    existing: &[YearlyPlan],
    updated: &[YearlyPlan],
) -> Result<()> {
    // 1) 기존 released=true 항목은 동일 release_time/amount/released=true로 보존되어야 함
    for old in existing.iter().filter(|p| p.released) {
        let matching = updated
            .iter()
            .find(|p| p.release_time == old.release_time)
            .ok_or(VestingError::AlreadyReleased)?;
        require!(matching.released, VestingError::AlreadyReleased);
        require!(
            matching.amount == old.amount,
            VestingError::InvalidParameters
        );
    }

    // 2) updated의 released=true는 반드시 기존 released tranche와 일치해야 함
    for new_plan in updated.iter().filter(|p| p.released) {
        let matching = existing
            .iter()
            .find(|p| p.release_time == new_plan.release_time && p.released)
            .ok_or(VestingError::InvalidParameters)?;
        require!(
            matching.amount == new_plan.amount,
            VestingError::InvalidParameters
        );
    }

    Ok(())
}

/// child vesting과 공급된 parent_plan_chunk / parent_vesting_account 관계 검증
fn assert_parent_chunk_binding(
    program_id: &Pubkey,
    child: &Account<VestingAccount>,
    parent_vesting: &Account<VestingAccount>,
    parent_chunk: &Account<VestingPlanChunk>,
) -> Result<()> {
    require_keys_eq!(
        parent_chunk.vesting_account,
        parent_vesting.key(),
        VestingError::InvalidParameters
    );

    let expected_parent_plan_chunk =
        Pubkey::find_program_address(&[b"plans", parent_vesting.key().as_ref()], program_id).0;
    require_keys_eq!(
        parent_chunk.key(),
        expected_parent_plan_chunk,
        VestingError::InvalidParameters
    );

    require!(!parent_chunk.plans.is_empty(), VestingError::InvalidParentPlan);

    let is_valid_parent_vault = child.parent_vault == parent_vesting.token_vault
        || child.parent_vault == parent_vesting.beneficiary_vault;
    require!(is_valid_parent_vault, VestingError::InvalidParameters);

    require_keys_eq!(
        child.token_mint,
        parent_vesting.token_mint,
        VestingError::InvalidParameters
    );

    Ok(())
}

/// 초기 생성 시 스케줄이 funding과 정확히 대응하는지 검증
fn validate_and_measure_initial_plans(
    plans: &[YearlyPlan],
    amount_to_transfer: u64,
    released_amount: u64,
) -> Result<()> {
    require!(!plans.is_empty(), VestingError::InvalidParameters);
    require!(plans.len() <= MAX_PLANS, VestingError::InvalidParameters);
    validate_yearly_plans(plans, false)?;

    let unreleased = sum_unreleased_amount(plans)?;
    let released = sum_released_amount(plans)?;

    // vault로 들어가는 금액 == 미해지 스케줄 합계
    require!(
        unreleased == amount_to_transfer,
        VestingError::InvalidParameters
    );
    // 이미 해지된 것으로 기록된 금액 == released plan 합계
    require!(
        released == released_amount,
        VestingError::InvalidParameters
    );

    Ok(())
}

/// 미해지 plan amount 합계
fn sum_unreleased_amount(plans: &[YearlyPlan]) -> Result<u64> {
    plans
        .iter()
        .filter(|p| !p.released)
        .map(|p| p.amount)
        .try_fold(0u64, |acc, amount| acc.checked_add(amount))
        .ok_or(VestingError::Overflow.into())
}

/// 해지 완료 plan amount 합계
fn sum_released_amount(plans: &[YearlyPlan]) -> Result<u64> {
    plans
        .iter()
        .filter(|p| p.released)
        .map(|p| p.amount)
        .try_fold(0u64, |acc, amount| acc.checked_add(amount))
        .ok_or(VestingError::Overflow.into())
}

/// vesting_account.total_amount / released_amount 와 plan 합계 불변식.
/// - 전체 plan 합계 <= total_amount
/// - released plan 합계 <= released_amount
/// - 미해지 plan 합계 <= total_amount - released_amount
fn assert_vesting_plan_cap(
    total_amount: u64,
    released_amount: u64,
    plans: &[YearlyPlan],
) -> Result<()> {
    require!(
        released_amount <= total_amount,
        VestingError::InvalidParameters
    );

    let mut plans_total: u64 = 0;
    let mut released_plans_total: u64 = 0;
    for plan in plans {
        plans_total = plans_total
            .checked_add(plan.amount)
            .ok_or(VestingError::Overflow)?;
        if plan.released {
            released_plans_total = released_plans_total
                .checked_add(plan.amount)
                .ok_or(VestingError::Overflow)?;
        }
    }

    require!(
        plans_total <= total_amount,
        VestingError::InsufficientAmount
    );
    require!(
        released_plans_total <= released_amount,
        VestingError::InvalidParameters
    );

    let unreleased_total = plans_total
        .checked_sub(released_plans_total)
        .ok_or(VestingError::Overflow)?;
    let remaining_cap = total_amount
        .checked_sub(released_amount)
        .ok_or(VestingError::Overflow)?;
    require!(
        unreleased_total <= remaining_cap,
        VestingError::InsufficientAmount
    );

    Ok(())
}

fn take_from_parent_plan(parent_plan_chunk: &mut VestingPlanChunk, plans: &[YearlyPlan]) -> Result<()> {
    let child_tge_time = plans.first().map(|p| p.release_time);  // User plan first release (assuming TGE)
    let parent_tge_time = parent_plan_chunk.plans.first().map(|p| p.release_time); // Parent first release
    let is_early_bird = child_tge_time == parent_tge_time;           // Check if TGE is the same

    if is_early_bird {
        require!(
            plans.len() == parent_plan_chunk.plans.len(),
            VestingError::InvalidParameters
        );
        // If TGE is the same, 1:1 matching (deduct only for released == false)
        for (child_plan, parent_plan) in plans.iter().zip(parent_plan_chunk.plans.iter_mut()) {
            if !child_plan.released && !parent_plan.released {
                require!(
                    parent_plan.amount >= child_plan.amount,
                    VestingError::InsufficientAmount
                );

                parent_plan.amount = parent_plan
                    .amount
                    .checked_sub(child_plan.amount)
                    .ok_or(VestingError::Overflow)?;           // Deduct amount from parent plan
            }
        }
    } else {
        // If TGE is different: match and deduct from user false[0] and parent false[1]
        // Extract only user plans where released == false
        let child_unreleased: Vec<&YearlyPlan> =
            plans.iter().filter(|p| !p.released).collect();
        let parent_unreleased: Vec<&mut YearlyPlan> = parent_plan_chunk
            .plans
            .iter_mut()
            .filter(|p| !p.released)
            .collect();

        // 1:1 correspondence from user 0, foundation 1
        let mut parent_iter = parent_unreleased.into_iter().skip(1);

        for child_plan in child_unreleased {
            if let Some(parent_plan) = parent_iter.next() {
                // Return error if foundation amount is insufficient
                require!(
                    parent_plan.amount >= child_plan.amount,
                    VestingError::InsufficientAmount
                );

                // Process deduction identically even if it's 0
                parent_plan.amount = parent_plan
                    .amount
                    .checked_sub(child_plan.amount)
                    .ok_or(VestingError::Overflow)?;
            } else {
                // If foundation plan is insufficient, stop further deductions and exit
                return Err(VestingError::InsufficientAmount.into());
            }
        }
    }
    
    Ok(())
}

fn return_to_parent_plan(parent_plan_chunk: &mut VestingPlanChunk, plans: &[YearlyPlan]) -> Result<()> {
    let child_tge_time = plans.first().map(|p| p.release_time);
    let parent_tge_time = parent_plan_chunk.plans.first().map(|p| p.release_time);
    let is_early_bird = child_tge_time == parent_tge_time;

    if is_early_bird {
        for (child_plan, parent_plan) in plans.iter().zip(parent_plan_chunk.plans.iter_mut()) {
            if !child_plan.released {
                parent_plan.amount = parent_plan
                    .amount.checked_add(child_plan.amount)
                    .ok_or(VestingError::Overflow)?;
            }
        }
    } else {
        let child_unreleased: Vec<&YearlyPlan> = plans.iter().filter(|p| !p.released).collect();
    let parent_unreleased: Vec<&mut YearlyPlan> = parent_plan_chunk.plans.iter_mut().filter(|p| !p.released).collect();
        let mut parent_iter = parent_unreleased.into_iter().skip(1);

        for child_plan in child_unreleased {
            if let Some(parent_plan) = parent_iter.next() {
                parent_plan.amount = parent_plan.amount
                    .checked_add(child_plan.amount)
                    .ok_or(VestingError::Overflow)?;
            } else {
                return Err(VestingError::InsufficientAmount.into());
            }
        }
    }
    
    Ok(())
}

// Store vesting information
#[account]
pub struct VestingAccount {                         // PDA to store vesting metadata
    pub beneficiary: Pubkey,                        // Beneficiary
    pub total_amount: u64,                          // Total amount
    pub released_amount: u64,                       // Cumulative released amount
    pub start_time: i64,                            // Start time (Unix)
    pub end_time: i64,                              // End time (Unix)
    pub last_release_time: i64,                     // Last release time
    pub token_mint: Pubkey,                         // Token mint
    pub token_vault: Pubkey,                        // Vault (for this vesting)
    pub beneficiary_vault: Pubkey,                  // Beneficiary vault (PDA)
    pub category: String,                           // Category (Team/Marketing, etc.)
    pub is_active: bool,                            // Is active?
    pub destination_token_account: Pubkey,          // Final receiving token account (e.g., ATA)
    pub parent_vault: Pubkey,                       // Parent vault (primary wallet)
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct YearlyPlan {                             // Yearly plan unit
    pub release_time: i64,                          // Release time
    pub amount: u64,                                // Release amount
    pub released: bool,                             // Has it been released already?
}

#[account]
pub struct VestingPlanChunk {                       // A bundle of plans (PDA)
    pub vesting_account: Pubkey,                    // Which vesting does it belong to
    pub plans: Vec<YearlyPlan>,                     // Array of YearlyPlan
}

// Account to store admin information
#[account]
pub struct AdminConfig {                            // Admin configuration (PDA)
    pub admin: Pubkey,                              // Admin key
}

#[account]
pub struct DeployAdmin {                            // Deployer configuration (PDA)
    pub deployer: Pubkey,                           // Deployer key
}

#[derive(Accounts)]
pub struct InitializeDeployer<'info> {              // initialize_deployer context
    #[account(mut)]
    pub deployer: Signer<'info>, // Deployer = signer

    #[account(
        init,
        payer = deployer,
        space = 8 + 32, // discriminator + pubkey
        seeds = [b"deploy_admin"],
        bump
    )]
    pub deploy_admin: Account<'info, DeployAdmin>,  // PDA: ("deploy_admin")

    pub system_program: Program<'info, System>,     // System program
}

// Struct for setting admin during program initialization
#[derive(Accounts)]
pub struct Initialize<'info> {                      // initialize context
    #[account(mut)]
    pub deployer: Signer<'info>,                    // Deployer signer

    #[account(
        seeds = [b"deploy_admin"],                 // Reuse PDA created above
        bump
    )]
    pub deployer_admin: Account<'info, DeployAdmin>,

    // Scheduler address
    #[account(mut)]
    pub admin: Signer<'info>,                       // Admin signer

    #[account(
        init,
        payer = admin,
        space = 8 + 32, // discriminator + pubkey
        seeds = [b"admin"],                         // Create AdminConfig PDA with a fixed seed
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(amount: u64, vesting_time: i64, params: VestingParams)]
pub struct DoVesting<'info> {                       // do_vesting context definition
    // Scheduler admin
    #[account(mut)]
    pub admin: Signer<'info>,                       // Calling admin

    #[account(mut)]
    pub token_vault: Account<'info, TokenAccount>,  // Related vault (used for authority PDA calculation)

    /// CHECK: PDA used as authority for token_vault (seeds: [b"vault_auth", admin.key, token_vault.key])
    pub vault_authority: UncheckedAccount<'info>,   // PDA itself is verified with seeds/bump

    #[account(
        mut,
        constraint = origin_token_account.mint == token_mint.key() @ VestingError::InvalidMint,
        constraint = origin_token_account.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub origin_token_account: Account<'info, TokenAccount>,   // Source token account (verification: PDA calculated directly above)

    #[account(
        mut,
        constraint = destination_token_account.mint == token_mint.key() @ VestingError::InvalidMint
    )]
    pub destination_token_account: Account<'info, TokenAccount>, // Destination token account (ATA verified)

    #[account(
        mut,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,         // The admin field must match this admin
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,            // Admin configuration PDA

    #[account(
        mut,
        seeds = [b"plans", vesting_account.key().as_ref()],   // Plan chunk PDA for this vesting
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()], // Registered token information PDA
        bump
    )]
    pub token_info: Box<Account<'info, TokenInfo>>,

    /// CHECK: Beneficiary
    pub beneficiary: AccountInfo<'info>,                      // Used for key check only
    pub token_mint: Account<'info, Mint>,                     // Token mint

    pub token_program: Program<'info, Token>,                 // SPL Token Program
    pub system_program: Program<'info, System>,               // System Program
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

    // register-before-deposit: TokenInfo가 없으면 예치 불가
    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()],
        bump,
        constraint = token_info.token_mint == token_mint.key() @ VestingError::InvalidToken
    )]
    pub token_info: Box<Account<'info, TokenInfo>>,

    #[account(
        mut,
        constraint = admin_token_account.mint == token_mint.key() @ VestingError::InvalidMint,
        constraint = admin_token_account.owner == admin.key() @ VestingError::Unauthorized
    )]
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

// Create vesting
#[derive(Accounts)]
#[instruction(params: VestingParams)]
pub struct CreateVesting<'info> {                 // create_vesting context
    // Scheduler address
    #[account(mut)]
    pub admin: Signer<'info>,                     // Admin signer

    #[account(
        has_one = admin @ VestingError::Unauthorized, // Must match AdminConfig.admin
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Box<Account<'info, TokenInfo>>, // Registered token information

    /// CHECK: Beneficiary
    pub beneficiary: AccountInfo<'info>,

    #[account(
        init,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()], // beneficiary+mint+id
        bump
    )]
    pub vesting_account: Account<'info, VestingAccount>,      // New vesting account

    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 4 + (MAX_PLANS * (8 + 8 + 1)),
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    pub token_mint: Account<'info, Mint>,

    // Top-level create: 자금 출처는 lockup된 admin vault PDA여야 함
    #[account(
        mut,
        seeds = [b"vault", admin_config.admin.as_ref(), token_mint.key().as_ref()],
        bump,
        constraint = token_vault.mint == token_mint.key() @ VestingError::InvalidMint,
        constraint = token_vault.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub token_vault: Box<Account<'info, TokenAccount>>,

    // parent_vault는 의도된 상위 vault(여기서는 admin lockup vault)와 반드시 동일
    #[account(
        mut,
        constraint = parent_vault.key() == token_vault.key() @ VestingError::InvalidParameters,
        constraint = parent_vault.mint == token_mint.key() @ VestingError::InvalidMint,
        constraint = parent_vault.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub parent_vault: Box<Account<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,
        seeds = [b"vault", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()], // Beneficiary-specific Vault
        bump
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,      // User-specific Vault

    /// CHECK: PDA used as the new authority for token_vault
    #[account(
        seeds = [b"vault_auth", admin.key().as_ref(), token_vault.key().as_ref()], // admin+token_vault 
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,             // Authority PDA (for transfer signature)
    // For primary wallet -> main vault -> on transfer, send from main vault to beneficiary_vault (primary wallet)
    #[account(mut)]
    pub beneficiary_token_account: Account<'info, TokenAccount>, // Beneficiary's final receiving ATA, etc.

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(params: VestingParams)]
pub struct UserCreateVesting<'info> {             // user_create_vesting context
    // Scheduler address
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, // Matches AdminConfig.admin
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        seeds = [b"token_info", admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Box<Account<'info, TokenInfo>>, // Token information

    /// CHECK: Beneficiary
    pub beneficiary: AccountInfo<'info>,

    #[account(
        init,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub vesting_account: Box<Account<'info, VestingAccount>>, // New vesting

    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 4 + (MAX_PLANS * (8 + 8 + 1)),
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    pub token_mint: Account<'info, Mint>,

    // Token minting wallet address + mint address
    #[account(
        mut,
        constraint = token_vault.key() == parent_vesting_account.token_vault @ VestingError::InvalidParameters,
        constraint = token_vault.mint == token_mint.key() @ VestingError::InvalidMint,
        constraint = token_vault.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub token_vault: Box<Account<'info, TokenAccount>>,       // Referenced vault

    // Primary wallet vault to transfer tokens to the secondary wallet
    #[account(
        mut,
        constraint = parent_vault.key() == parent_vesting_account.beneficiary_vault @ VestingError::InvalidParameters,
        constraint = parent_vault.mint == token_mint.key() @ VestingError::InvalidMint,
        constraint = parent_vault.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub parent_vault: Box<Account<'info, TokenAccount>>,      // Parent vault

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,
        seeds = [b"vault", beneficiary.key().as_ref(), token_mint.key().as_ref(), &params.vesting_id.to_le_bytes()],
        bump
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,

    /// CHECK: PDA used as the new authority for token_vault
    #[account(
        seeds = [b"vault_auth", admin.key().as_ref(), token_vault.key().as_ref()],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,
    // For primary wallet -> main vault -> on transfer, send from main vault to beneficiary_vault (primary wallet)
    #[account(mut)]
    pub beneficiary_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub parent_vesting_account: Box<Account<'info, VestingAccount>>,   // Parent vesting

    #[account(
        mut,
        seeds = [b"plans", parent_vesting_account.key().as_ref()],     // Parent plan chunk
        bump
    )]
    pub parent_plan_chunk: Box<Account<'info, VestingPlanChunk>>,      // Parent plans

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct AppendYearlyPlan<'info> {               // append_yearly_plan context
    #[account(mut)]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + 32 + 4 + (MAX_PLANS * (8 + 8 + 1)),                // Max 52 plans (size calculation in comments)
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,                  // Create/update the target plan chunk

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
pub struct UpdatePlanChunk<'info> {               // update_plan_chunk context
    #[account(mut)]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        mut,
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(mut)]
    pub parent_plan_chunk: Option<Account<'info, VestingPlanChunk>>,

    /// CHECK: parent vesting account — child update 시 parent plan 바인딩에 필요
    pub parent_vesting_account: Option<Account<'info, VestingAccount>>,

    // Child vault (funded allocation)
    #[account(
        mut,
        constraint = beneficiary_vault.key() == vesting_account.beneficiary_vault @ VestingError::InvalidParameters,
        constraint = beneficiary_vault.mint == vesting_account.token_mint @ VestingError::InvalidMint,
        constraint = beneficiary_vault.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,

    // Parent vault that originally funded the child
    #[account(
        mut,
        constraint = parent_vault.key() == vesting_account.parent_vault @ VestingError::InvalidParameters,
        constraint = parent_vault.mint == vesting_account.token_mint @ VestingError::InvalidMint,
        constraint = parent_vault.owner == vault_authority.key() @ VestingError::Unauthorized
    )]
    pub parent_vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = token_vault.key() == vesting_account.token_vault @ VestingError::InvalidParameters
    )]
    pub token_vault: Account<'info, TokenAccount>,

    /// CHECK: PDA authority for parent/child vaults
    #[account(
        seeds = [b"vault_auth", admin.key().as_ref(), token_vault.key().as_ref()],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct EmergencyStop<'info> {                 // emergency_stop context
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// CHECK: beneficiary account
    pub beneficiary: AccountInfo<'info>,          // Key check only

    pub token_mint: Account<'info, Mint>,

    #[account(
        mut,
        constraint = vesting_account.beneficiary == beneficiary.key() @ VestingError::Unauthorized, // Beneficiary must match
        constraint = vesting_account.token_mint == token_mint.key() @ VestingError::Unauthorized   // Token must match
    )]
    pub vesting_account: Account<'info, VestingAccount>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VestingParams {                        // Parameters for creating/releasing vesting
    pub vesting_id: u64,                          // Identifier (PDA seed)
    pub total_amount: u64,                        // Total amount
    pub released_amount: u64,                     // Already released amount (initial transfer allowed)
    pub start_time: i64,                          // Start time
    pub end_time: i64,                            // End time
    pub category: String,                         // Category
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VestingInfo {                          // (For querying) Vesting summary info struct
    pub total_amount: u64,
    pub released_amount: u64,
    pub releasable_amount: u64,
    pub next_release_time: i64,
    pub is_active: bool,
}

// Return PDA rent
#[derive(Accounts)]
pub struct CloseVestingAccount<'info> {           // close_vesting_account context
    // Scheduler admin
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(mut, close = admin)]
    pub vesting_account: Account<'info, VestingAccount>,      // On close, return rent to admin

    #[account(
        mut,
        close = admin,
        seeds = [b"plans", vesting_account.key().as_ref()],  // Close plan chunk as well
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(
        constraint = beneficiary_vault.key() == vesting_account.beneficiary_vault @ VestingError::Unauthorized,
        constraint = beneficiary_vault.amount == 0 @ VestingError::VaultNotEmpty, // Close only if vault is empty
    )]
    pub beneficiary_vault: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveAdmin<'info> {                   // remove_admin context
    #[account(mut)]
    pub deployer: Signer<'info>,                  // Deployer signer

    #[account(
        seeds = [b"deploy_admin"],
        bump
    )]
    pub deployer_admin: Account<'info, DeployAdmin>,

    #[account(mut)]
    /// CHECK: admin account, ownership checks etc. are handled directly in the code
    pub admin: AccountInfo<'info>,                // Simple AccountInfo

    #[account(
        mut,
        close = deployer,
        seeds = [b"admin"],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,           // Close AdminConfig and return rent to deployer
}

#[account]
pub struct TokenInfo {                            // Token metadata (PDA)
    pub token_name: String,
    pub token_symbol: String,
    pub total_supply: u64,
    pub token_mint: Pubkey,
    pub mint_wallet_address: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct TokenInfoArgs {                        // Input parameters for init_token_info
    pub token_name: String,
    pub token_symbol: String,
    pub total_supply: u64,
    pub token_mint: Pubkey,
    pub mint_wallet_address: Pubkey,
}

#[derive(Accounts)]
pub struct InitTokenInfo<'info> {                 // init_token_info context
    #[account(mut)]
    pub scheduler_admin: Signer<'info>,           // Caller (scheduler admin)

    #[account(
        init,
        payer = scheduler_admin,
        space = DISCRIMINATOR_SIZE
            + (STRING_LENGTH_PREFIX + TOKEN_NAME_MAX_LEN)
            + (STRING_LENGTH_PREFIX + TOKEN_SYMBOL_MAX_LEN)
            + 8   // total_supply
            + 32  // token_mint
            + 32, // mint_wallet_address
        seeds = [b"token_info", scheduler_admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_info: Account<'info, TokenInfo>,    // New TokenInfo PDA

    #[account(
        seeds = [b"admin"],                      // Existing AdminConfig (read-only)
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub token_mint: Account<'info, Mint>,         // Mint

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum VestingError {                           // Custom error definitions
    #[msg("Veseting period has not ended yet")]
    VestingNotReached,                            // Release time not yet reached
    #[msg("No tokens available for release")]
    NoTokensToRelease,                            // No tokens to release
    #[msg("Unauthorized operation")]
    Unauthorized,                                 // Unauthorized
    #[msg("Vesting is not active")]
    NotActive,                                    // Inactive state
    #[msg("Invalid vesting parameters")]
    InvalidParameters,                            // Invalid parameters
    #[msg("Add amount is overflow")]
    Overflow,                                     // Overflow
    #[msg("You are not the deployer admin.")]
    NotDeployAdmin,                               // Not the deployer
    #[msg("Invalid parent vesting plan.")]
    InvalidParentPlan,                            // Invalid parent plan
    #[msg("Insufficient amount in the parent vesting plan.")]
    InsufficientAmount,                           // Insufficient amount in parent plan
    #[msg("Plans can be appended up to 52.")]
    InsufficientSpace,                            // Insufficient space
    #[msg("Vesting for the specified time has already been completed.")]
    AlreadyReleased,                              // Already released for this time
    #[msg("Token not registered in token_info.")]
    InvalidToken,                                 // Unregistered token
    #[msg("Vault must be empty before closing the vesting account.")]
    VaultNotEmpty,                                // Vault must have a zero balance
    #[msg("Invalid Mint")]
    InvalidMint,                                  // Mint mismatch
}