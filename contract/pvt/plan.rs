use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("EsBXrK3qZJzPGkiqMesZeKXPTrJk9FU2X95TgiLCnfQA");

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
        let admin_config = &mut ctx.accounts.admin_config;
        admin_config.admin = ctx.accounts.admin.key();
        Ok(())
    }

    pub fn do_vesting(ctx: Context<DoVesting>, amount: u64, vesting_time: i64) -> Result<()> {
        let now = Clock::get()?;
        let vesting_account = &mut ctx.accounts.vesting_account;
        let admin = &ctx.accounts.admin;
        let admin_config = &ctx.accounts.admin_config;

        require!(
            admin_config.admin == admin.key(),
            VestingError::Unauthorized
        );
        require!(vesting_account.is_active, VestingError::NotActive);
        require!(
            vesting_account.last_release_time <= now.unix_timestamp,
            VestingError::VestingNotReached
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

        // 파라미터 유효성 검사
        require!(params.total_amount > 0, VestingError::InvalidParameters);
        // require!(
        //     params.end_time > clock.unix_timestamp,
        //     VestingError::InvalidParameters
        // );

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
            params.total_amount,
        )?;

        emit!(VestingCreated {
            beneficiary: ctx.accounts.beneficiary.key(),
            total_amount: params.total_amount,
            start_time: vesting_account.start_time,
            category: params.category.clone(),
            updated_timestamp: Some(Clock::get()?.unix_timestamp),
        });

        Ok(())
    }

    pub fn user_create_vesting(
        ctx: Context<UserCreateVesting>,
        params: VestingParams,
    ) -> Result<()> {
        let _vesting_account_info = ctx.accounts.vesting_account.to_account_info();
        let vesting_account = &mut ctx.accounts.vesting_account;
        let _clock = Clock::get()?;

        // admin인지 검사
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        // 파라미터 유효성 검사
        require!(params.total_amount > 0, VestingError::InvalidParameters);
        // require!(
        //     params.end_time > clock.unix_timestamp,
        //     VestingError::InvalidParameters
        // );

        let plans = &mut ctx.accounts.parent_plan_chunk.plans;
        require!(!plans.is_empty(), VestingError::ParentPlanNotFound);

        let first_plan = &mut plans[0];
        require!(
            first_plan.amount >= params.total_amount,
            VestingError::InsufficientAmount
        );

        first_plan.amount = first_plan
            .amount
            .checked_sub(params.total_amount)
            .ok_or(VestingError::Overflow)?;

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
            params.total_amount,
        )?;

        emit!(VestingCreated {
            beneficiary: ctx.accounts.beneficiary.key(),
            total_amount: params.total_amount,
            start_time: vesting_account.start_time,
            category: params.category.clone(),
            updated_timestamp: Some(Clock::get()?.unix_timestamp),
        });

        Ok(())
    }

    pub fn append_yearly_plan(
        ctx: Context<AppendYearlyPlan>,
        plans: Vec<YearlyPlan>,
    ) -> Result<()> {
        let chunk = &mut ctx.accounts.plan_chunk;
        chunk.vesting_account = ctx.accounts.vesting_account.key();
        chunk.plans.extend(plans);
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

        emit!(EmergencyStopped {
            vesting_account: ctx.accounts.vesting_account.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    pub fn get_vesting_info(ctx: Context<GetVestingInfo>) -> Result<VestingInfo> {
        let vesting_account = &ctx.accounts.vesting_account;
        let clock = Clock::get()?;
        let _current_time = clock.unix_timestamp;

        // 새로운 로직으로 대체 가능 (예: releasable_amount = total_amount - released_amount, next_release_time = end_time)
        Ok(VestingInfo {
            total_amount: vesting_account.total_amount,
            released_amount: vesting_account.released_amount,
            releasable_amount: vesting_account
                .total_amount
                .saturating_sub(vesting_account.released_amount),
            next_release_time: vesting_account.end_time,
            is_active: vesting_account.is_active,
        })
    }

    // 수혜자 지갑 업데이트
    pub fn update_beneficiary(ctx: Context<UpdateBeneficiary>) -> Result<()> {
        let vesting_account = &mut ctx.accounts.vesting_account;

        // admin 권한 검증
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        // 새로운 beneficiary와 destination_token_account 설정
        vesting_account.beneficiary = ctx.accounts.new_beneficiary.key();
        vesting_account.destination_token_account =
            ctx.accounts.new_beneficiary_token_account.key();

        emit!(BeneficiaryUpdated {
            vesting_account: ctx.accounts.vesting_account.key(),
            old_beneficiary: ctx.accounts.old_beneficiary.key(),
            new_beneficiary: ctx.accounts.new_beneficiary.key(),
            new_destination: ctx.accounts.new_beneficiary_token_account.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    // vesting_account 업데이트
    pub fn update_vesting_info(
        ctx: Context<UpdateVestingInfo>,
        params: UpdateVestingParams,
    ) -> Result<()> {
        let vesting_account = &mut ctx.accounts.vesting_account;

        // admin 권한 검증
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        // 파라미터 유효성 검사
        if let Some(total_amount) = params.total_amount {
            require!(total_amount > 0, VestingError::InvalidParameters);
            vesting_account.total_amount = total_amount;
        }
        // releaseAmount 업데이트
        if let Some(release_amount) = params.release_amount {
            require!(
                release_amount <= vesting_account.total_amount,
                VestingError::InvalidParameters
            );
            vesting_account.released_amount = release_amount;
        }
        // start_time 업데이트
        if let Some(start_time) = params.start_time {
            require!(start_time > 0, VestingError::InvalidParameters);
            vesting_account.start_time = start_time;
        }
        // end_time 업데이트
        if let Some(end_time) = params.end_time {
            require!(end_time > 0, VestingError::InvalidParameters);
            vesting_account.end_time = end_time;
        }
        // token_mint 업데이트
        if let Some(token_mint) = params.token_mint {
            vesting_account.token_mint = token_mint;
        }
        // token_vault 업데이트
        if let Some(token_vault) = params.token_vault {
            vesting_account.token_vault = token_vault;
        }
        // category 업데이트
        if let Some(category) = params.category {
            vesting_account.category = category;
        }
        // updated_timestamp 추가 등록 (업데이트한 시간 알기 위해)
        // if let Some(updated_timestamp) = params.updated_timestamp {
        //     vesting_account.updated_timestamp = Some(updated_timestamp);
        // }

        emit!(VestingUpdated {
            vesting_account: vesting_account.key(),
            total_amount: vesting_account.total_amount,
            released_amount: vesting_account.released_amount,
            start_time: vesting_account.start_time,
            end_time: vesting_account.end_time,
            token_mint: vesting_account.token_mint,
            token_vault: vesting_account.token_vault,
            category: vesting_account.category.clone(),
            updated_timestamp: Some(Clock::get()?.unix_timestamp),
        });

        Ok(())
    }

    pub fn close_vesting_account(_ctx: Context<CloseVestingAccount>) -> Result<()> {
        Ok(())
    }

    pub fn update_vesting_time(
        ctx: Context<UpdateVestingInfo>,
        args: UpdateVestingTimeArgs,
    ) -> Result<()> {
        let vesting_account = &mut ctx.accounts.vesting_account;

        vesting_account.start_time = args.new_start_time;
        vesting_account.end_time = args.new_end_time;

        Ok(())
    }

    pub fn remove_admin(ctx: Context<RemoveAdmin>) -> Result<()> {
        require!(
            ctx.accounts.deployer_admin.deployer == ctx.accounts.deployer.key(),
            VestingError::NotDeployAdmin
        );

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
    // 스케줄러 주소
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = 8 + 32, // discriminator + pubkey
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
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

    #[account(
        init_if_needed,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub vesting_account: Account<'info, VestingAccount>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(
        mut,
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    /// CHECK: 수혜자
    pub beneficiary: AccountInfo<'info>,
    pub token_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct LockupVault<'info> {
    #[account(mut)]
    // 토큰 발행자 주소
    pub admin: Signer<'info>,

    /// CHECK: 스케줄러 주소
    #[account(mut)]
    pub scheduler_admin: AccountInfo<'info>,

    #[account(mut)]
    pub admin_token_account: Account<'info, TokenAccount>,
    pub token_mint: Account<'info, Mint>,

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,
        seeds = [b"vault", admin.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub token_vault: Account<'info, TokenAccount>,

    /// CHECK: token_vault의 새로운 authority로 사용하는 PDA
    #[account(
        seeds = [b"vault_auth", scheduler_admin.key().as_ref(), token_vault.key().as_ref()],
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

// 베스팅 생성
#[derive(Accounts)]
pub struct CreateVesting<'info> {
    // 스케줄러 주소
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, // admin 계정 검사
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// CHECK: 수혜자
    pub beneficiary: AccountInfo<'info>,

    #[account(
        init,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub vesting_account: Account<'info, VestingAccount>,

    pub token_mint: Account<'info, Mint>,

    /// CHECK: 토큰 발행 지갑 주소
    #[account(mut)]
    pub mint_admin: AccountInfo<'info>,

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
        seeds = [b"vault", beneficiary.key().as_ref(), token_mint.key().as_ref()],
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
pub struct UserCreateVesting<'info> {
    // 스케줄러 주소
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized, // admin 계정 검사
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    /// CHECK: 수혜자
    pub beneficiary: AccountInfo<'info>,

    #[account(
        init,
        payer = admin,
        space = VESTING_ACCOUNT_SPACE,
        seeds = [b"vesting", beneficiary.key().as_ref(), token_mint.key().as_ref()],
        bump
    )]
    pub vesting_account: Account<'info, VestingAccount>,

    pub token_mint: Account<'info, Mint>,

    /// CHECK: 토큰 발행 지갑 주소
    #[account(mut)]
    pub mint_admin: AccountInfo<'info>,

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
        seeds = [b"vault", beneficiary.key().as_ref(), token_mint.key().as_ref()],
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
        space = 8 + 32 + 4 + (52 * (8 + 8 + 8)),
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdatePlanChunk<'info> {
    #[account(mut)]
    pub plan_chunk: Account<'info, VestingPlanChunk>,
}

#[derive(Accounts)]
pub struct EmergencyStop<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin", admin.key().as_ref()],
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

#[derive(Accounts)]
pub struct GetVestingInfo<'info> {
    pub vesting_account: Account<'info, VestingAccount>,
}

#[derive(Accounts)]
pub struct UpdateBeneficiary<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(mut)]
    pub vesting_account: Account<'info, VestingAccount>,

    /// CHECK: 이전 수혜자
    pub old_beneficiary: AccountInfo<'info>,

    /// CHECK: 새로운 수혜자
    pub new_beneficiary: AccountInfo<'info>,

    /// CHECK: 새로운 수혜자의 토큰 계정
    pub new_beneficiary_token_account: Account<'info, TokenAccount>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct VestingParams {
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

// vesting_account 업데이트용 파라미터 구조체
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct UpdateVestingParams {
    pub total_amount: Option<u64>,
    pub release_amount: Option<u64>,
    pub start_time: Option<i64>,
    pub end_time: Option<i64>,
    pub token_mint: Option<Pubkey>,
    pub token_vault: Option<Pubkey>,
    pub category: Option<String>,
}

// vesting_account 업데이트 계정 구조체
#[derive(Accounts)]
pub struct UpdateVestingInfo<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin @ VestingError::Unauthorized,
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(mut)]
    pub vesting_account: Account<'info, VestingAccount>,
}

// PDA 렌트비 반환
#[derive(Accounts)]
pub struct CloseVestingAccount<'info> {
    // 스케줄러 어드민
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        has_one = admin,
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,

    #[account(mut, close = admin)]
    pub vesting_account: Account<'info, VestingAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct UpdateVestingTimeArgs {
    pub new_start_time: i64,
    pub new_end_time: i64,
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

    pub admin: AccountInfo<'info>,

    #[account(
        mut,
        close = deployer,
        seeds = [b"admin", admin.key().as_ref()],
        bump
    )]
    pub admin_config: Account<'info, AdminConfig>,
}

#[event]
pub struct VestingUpdated {
    pub vesting_account: Pubkey,
    pub total_amount: u64,
    pub released_amount: u64,
    pub start_time: i64,
    pub end_time: i64,
    pub token_mint: Pubkey,
    pub token_vault: Pubkey,
    pub category: String,
    pub updated_timestamp: Option<i64>,
}
#[event]
pub struct VestingCreated {
    pub beneficiary: Pubkey,
    pub total_amount: u64,
    pub start_time: i64,
    pub category: String,
    pub updated_timestamp: Option<i64>,
}

#[event]
pub struct EmergencyStopped {
    pub vesting_account: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct BeneficiaryUpdated {
    pub vesting_account: Pubkey,
    pub old_beneficiary: Pubkey,
    pub new_beneficiary: Pubkey,
    pub new_destination: Pubkey,
    pub timestamp: i64,
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
}
