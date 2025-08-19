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

        msg!("vesting_account = {}", vesting_account.key());
        msg!("beneficiary = {}", vesting_account.beneficiary.key());
        msg!("token_mint = {}", vesting_account.token_mint.key());
        msg!("params.vesting_id  = {}", params.vesting_id);

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
            dest.key() == expected_ata && dest.owner == ctx.accounts.vault_authority.key();
        let is_admin_ata =
            dest.key() == admin_ata && dest.owner == ctx.accounts.vault_authority.key();

        require!(
            is_beneficiary_ata || is_admin_ata,
            VestingError::Unauthorized
        );

        // require_keys_eq!(
        //     ctx.accounts.destination_token_account.key(),
        //     expected_ata,
        //     VestingError::InvalidParameters
        // );

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

        // 파라미터 유효성 검사
        require!(params.total_amount > 0, VestingError::InvalidParameters);

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

        let chunk = &mut ctx.accounts.plan_chunk;
        let deduct = ctx.accounts.vesting_account.token_vault.key()
            != ctx.accounts.vesting_account.parent_vault.key();

        if deduct {
            // 해당 프로그램 소유인지 확인
            let ai = ctx
                .accounts
                .parent_plan_chunk
                .as_ref()
                .unwrap()
                .to_account_info();
            require!(ai.owner == ctx.program_id, VestingError::Unauthorized);

            let parent_chunk = ctx
                .accounts
                .parent_plan_chunk
                .as_deref_mut()
                .ok_or(VestingError::ParentPlanNotFound)?;

            let user_tge_time = plans.first().map(|p| p.release_time);
            let parent_tge_time = parent_chunk.plans.first().map(|p| p.release_time);
            let tge_equal = user_tge_time == parent_tge_time;

            if tge_equal {
                // TGE 같으면 1:1 매칭 (released == false인 것만 차감)
                for (user_plan, parent_plan) in plans.iter().zip(parent_chunk.plans.iter_mut()) {
                    if !user_plan.released && !parent_plan.released {
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
            } else {
                // TGE 다르면: user false[0]부터, parent false[1]부터 매칭해서 차감
                // 유저의 released == false 플랜만 추출
                let user_unreleased: Vec<&YearlyPlan> =
                    plans.iter().filter(|p| !p.released).collect();
                let parent_unreleased: Vec<&mut YearlyPlan> = parent_chunk
                    .plans
                    .iter_mut()
                    .filter(|p| !p.released)
                    .collect();

                // 유저 0부터, 재단 1부터 1:1 대응
                let mut parent_iter = parent_unreleased.into_iter().skip(1);

                for user_plan in user_unreleased {
                    if let Some(parent_plan) = parent_iter.next() {
                        // 재단 amount가 부족한 경우 에러 반환
                        require!(
                            parent_plan.amount >= user_plan.amount,
                            VestingError::InsufficientAmount
                        );

                        // 0이라도 동일하게 차감 처리
                        parent_plan.amount = parent_plan
                            .amount
                            .checked_sub(user_plan.amount)
                            .ok_or(VestingError::Overflow)?;
                    } else {
                        // ❗️재단 플랜이 부족하면 더 이상 차감하지 않고 종료
                        break;
                    }
                }
            }
        }

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

    #[account(mut)]
    pub parent_plan_chunk: Option<Account<'info, VestingPlanChunk>>,

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
