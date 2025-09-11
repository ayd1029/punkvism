use anchor_lang::prelude::*;                          // Anchor basic prelude: Import accounts, macros, and types
use anchor_spl::associated_token::get_associated_token_address; // SPL ATA utility: Function for calculating ATA
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer}; // Types/functions used for SPL Token CPI

declare_id!("DcjmKSSKNxbSAwBQZx8wSAhosxBxQoyz3DdXuysMiPTy"); // Declare program ID (on-chain program id)

const CATEGORY_MAX_LEN: usize = 50;                   // Maximum length for the category string
const DISCRIMINATOR_SIZE: usize = 8;                  // Anchor account discriminator (8 bytes)
const STRING_LENGTH_PREFIX: usize = 4; // String length prefix (u32) - Anchor prepends this during String serialization

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
        let plan = &mut vesting_plan
            .plans
            .iter_mut()
            .find(|p| p.release_time == vesting_time)          // Find a plan that matches the request time
            .ok_or(VestingError::InvalidParameters)?;          // Error if not found

        require!(
            plan.release_time <= now.unix_timestamp,           // Has the time for that plan passed?
            VestingError::VestingNotReached
        );
        require!(!plan.released, VestingError::AlreadyReleased); // Cannot proceed if the plan has already been released
        require!(plan.amount == amount, VestingError::InvalidParameters); // The requested amount must match the plan's amount

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

    pub fn lockup_vault(ctx: Context<LockupVault>, amount: u64) -> Result<()> { // Lock tokens from admin wallet to vault
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.admin_token_account.to_account_info(), // Admin's token account
                    to: ctx.accounts.token_vault.to_account_info(),           // Program vault
                    authority: ctx.accounts.admin.to_account_info(),          // Admin signature
                },
            ),
            amount,
        )?;
        Ok(())
    }

    pub fn create_vesting(ctx: Context<CreateVesting>, params: VestingParams) -> Result<()> { // Create vesting account
        let _vesting_account_info = ctx.accounts.vesting_account.to_account_info(); // (Unused) account handle
        let vesting_account = &mut ctx.accounts.vesting_account; // Mutable reference
        let _clock = Clock::get()?;                              // (Unused) time

        // Check if admin
        require!(
            ctx.accounts.admin.key() == ctx.accounts.admin_config.admin,
            VestingError::Unauthorized
        );

        require!(
            ctx.accounts.token_info.token_mint == ctx.accounts.token_mint.key(), // Verify if it is a registered token
            VestingError::InvalidToken
        );

        // Parameter validation
        require!(params.total_amount > 0, VestingError::InvalidParameters);

        require!(
            ctx.accounts.beneficiary_vault.key() != ctx.accounts.parent_vault.key(), // Same vault is prohibited
            VestingError::InvalidParameters
        );

        let amount_to_transfer = params                         // Amount to move from parent_vault to beneficiary_vault
            .total_amount
            .checked_sub(params.released_amount)
            .ok_or(VestingError::InvalidParameters)?;

        vesting_account.beneficiary = ctx.accounts.beneficiary.key(); // Beneficiary address
        vesting_account.total_amount = params.total_amount;           // Total vesting amount
        vesting_account.released_amount = params.released_amount;     // Already released amount (initial value allowed)
        vesting_account.start_time = params.start_time;               // Start time
        // vesting_account.cliff_time = params.cliff_time;            // (Comment) Cliff not used
        vesting_account.end_time = params.end_time;                   // End time
        vesting_account.token_mint = ctx.accounts.token_mint.key();   // Vesting token mint
        vesting_account.token_vault = ctx.accounts.token_vault.key(); // Token vault
        vesting_account.beneficiary_vault = ctx.accounts.beneficiary_vault.key(); // Beneficiary vault

        vesting_account.destination_token_account = ctx.accounts.beneficiary_token_account.key(); // Final receiving account
        vesting_account.category = params.category.clone();            // Category (Team/Marketing, etc.)
        vesting_account.is_active = true;                              // Activate
        vesting_account.parent_vault = ctx.accounts.parent_vault.key(); // Record parent vault

        let admin_key = ctx.accounts.admin.key();
        let token_vault_key = ctx.accounts.token_vault.key();

        let (_vault_auth, vault_auth_bump) = Pubkey::find_program_address( // Authority PDA (bump)
            &[b"vault_auth", admin_key.as_ref(), token_vault_key.as_ref()],
            ctx.program_id,
        );

        let signer_seeds: &[&[u8]; 4] = &[
            b"vault_auth",
            admin_key.as_ref(),
            token_vault_key.as_ref(),
            &[vault_auth_bump],
        ];

        token::transfer(                                               // Move parent_vault -> beneficiary_vault
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
    ) -> Result<()> {                                                   // Create user vesting based on parent plan
        let vesting_account = &mut ctx.accounts.vesting_account;
        let _clock = Clock::get()?;

        // Check if admin
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

        let plans = &mut ctx.accounts.parent_plan_chunk.plans;         // Parent plans
        require!(!plans.is_empty(), VestingError::ParentPlanNotFound);  // Not possible if parent plan does not exist

        let amount_to_transfer = params
            .total_amount
            .checked_sub(params.released_amount)
            .ok_or(VestingError::InvalidParameters)?;

        vesting_account.beneficiary = ctx.accounts.beneficiary.key();
        vesting_account.total_amount = params.total_amount;
        vesting_account.released_amount = params.released_amount;
        vesting_account.start_time = params.start_time;
        vesting_account.end_time = params.end_time;
        vesting_account.token_mint = ctx.accounts.token_mint.key();
        vesting_account.token_vault = ctx.accounts.token_vault.key();
        vesting_account.beneficiary_vault = ctx.accounts.beneficiary_vault.key();

        vesting_account.destination_token_account = ctx.accounts.beneficiary_token_account.key();
        vesting_account.category = params.category.clone();
        vesting_account.is_active = true;
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
    ) -> Result<()> {                                                  // Add yearly plan (and parent deduction logic)
        require!(
            ctx.accounts.admin_config.admin == ctx.accounts.admin.key(), // Check admin
            VestingError::Unauthorized
        );

        let chunk = &mut ctx.accounts.plan_chunk;                       // Target plan chunk
        let deduct = ctx.accounts.vesting_account.token_vault.key()
            != ctx.accounts.vesting_account.parent_vault.key();         // Perform parent deduction if different from parent vault

        if deduct {
            // Check if owned by this program
            let ai = ctx
                .accounts
                .parent_plan_chunk
                .as_ref()
                .unwrap()
                .to_account_info();                                     // Option unwrap (assuming it exists beforehand)
            require!(ai.owner == ctx.program_id, VestingError::Unauthorized); // Must be owned by the same program

            let parent_chunk = ctx
                .accounts
                .parent_plan_chunk
                .as_deref_mut()
                .ok_or(VestingError::ParentPlanNotFound)?;             // Check for parent plan existence

            let user_tge_time = plans.first().map(|p| p.release_time);  // User plan first release (assuming TGE)
            let parent_tge_time = parent_chunk.plans.first().map(|p| p.release_time); // Parent first release
            let tge_equal = user_tge_time == parent_tge_time;           // Check if TGE is the same

            if tge_equal {
                // If TGE is the same, 1:1 matching (deduct only for released == false)
                for (user_plan, parent_plan) in plans.iter().zip(parent_chunk.plans.iter_mut()) {
                    if !user_plan.released && !parent_plan.released {
                        require!(
                            parent_plan.amount >= user_plan.amount,
                            VestingError::InsufficientAmount
                        );

                        parent_plan.amount = parent_plan
                            .amount
                            .checked_sub(user_plan.amount)
                            .ok_or(VestingError::Overflow)?;           // Deduct amount from parent plan
                    }
                }
            } else {
                // If TGE is different: match and deduct from user false[0] and parent false[1]
                // Extract only user plans where released == false
                let user_unreleased: Vec<&YearlyPlan> =
                    plans.iter().filter(|p| !p.released).collect();
                let parent_unreleased: Vec<&mut YearlyPlan> = parent_chunk
                    .plans
                    .iter_mut()
                    .filter(|p| !p.released)
                    .collect();

                // 1:1 correspondence from user 0, foundation 1
                let mut parent_iter = parent_unreleased.into_iter().skip(1);

                for user_plan in user_unreleased {
                    if let Some(parent_plan) = parent_iter.next() {
                        // Return error if foundation amount is insufficient
                        require!(
                            parent_plan.amount >= user_plan.amount,
                            VestingError::InsufficientAmount
                        );

                        // Process deduction identically even if it's 0
                        parent_plan.amount = parent_plan
                            .amount
                            .checked_sub(user_plan.amount)
                            .ok_or(VestingError::Overflow)?;
                    } else {
                        // If foundation plan is insufficient, stop further deductions and exit
                        break;
                    }
                }
            }
        }

        chunk.vesting_account = ctx.accounts.vesting_account.key(); // Indicate the owning vesting account
        chunk.plans.extend(plans);                                   // Add plans
        Ok(())
    }

    pub fn update_plan_chunk(ctx: Context<UpdatePlanChunk>, plans: Vec<YearlyPlan>) -> Result<()> { // Replace all plans
        let plan_chunk = &mut ctx.accounts.plan_chunk;

        plan_chunk.plans.clear();                                     // Delete existing
        plan_chunk.plans.extend(plans);                               // Refill with new

        Ok(())
    }

    // Emergency stop function (change is_active state)
    pub fn emergency_stop(ctx: Context<EmergencyStop>) -> Result<()> { // Toggle between active/inactive
        let vesting_account = &mut ctx.accounts.vesting_account;
        vesting_account.is_active = !vesting_account.is_active;        // Toggle

        Ok(())
    }

    pub fn close_vesting_account(_ctx: Context<CloseVestingAccount>) -> Result<()> { // (Handle only)
        Ok(())                                                         // Actual resource deallocation is performed by the account annotation
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

        let token_info = &mut ctx.accounts.token_info;                 // TokenInfo PDA

        token_info.token_name = args.token_name;                       // Set name/symbol/total supply/mint/minting wallet
        token_info.token_symbol = args.token_symbol;
        token_info.total_supply = args.total_supply;
        token_info.token_mint = args.token_mint;
        token_info.mint_wallet_address = args.mint_wallet_address;

        Ok(())
    }

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
pub struct LockupVault<'info> {                    // lockup_vault context
    #[account(mut)]
    // Token issuer address
    pub admin: Signer<'info>,                      // Admin signer

    /// CHECK: Scheduler address
    #[account(mut)]
    pub scheduler_admin: AccountInfo<'info>,       // Scheduler (can be matched with AdminConfig.admin)

    #[account(mut)]
    pub admin_token_account: Account<'info, TokenAccount>, // Admin's token account
    pub token_mint: Account<'info, Mint>,                  // Mint

    #[account(
        init_if_needed,
        payer = admin,
        token::mint = token_mint,
        token::authority = vault_authority,        // Assign vault_authority PDA as the new authority
        seeds = [b"vault", admin.key().as_ref(), token_mint.key().as_ref()], // Vault PDA based on admin/mint
        bump
    )]
    pub token_vault: Account<'info, TokenAccount>, // Vault (admin+mint)

    /// CHECK: PDA used as the new authority for token_vault
    #[account(
        seeds = [b"vault_auth", scheduler_admin.key().as_ref(), token_vault.key().as_ref()], // scheduler+vault
        bump
    )]
    pub vault_authority: UncheckedAccount<'info>,  // Vault authority PDA

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

    pub token_mint: Account<'info, Mint>,

    // Token minting wallet address + mint address
    #[account(mut)]
    pub token_vault: Box<Account<'info, TokenAccount>>,       // The vault this vesting references

    // Primary wallet vault to transfer tokens to the secondary wallet
    #[account(mut)]
    pub parent_vault: Box<Account<'info, TokenAccount>>,      // Parent vault (main)

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

    pub token_mint: Account<'info, Mint>,

    // Token minting wallet address + mint address
    #[account(mut)]
    pub token_vault: Box<Account<'info, TokenAccount>>,       // Referenced vault

    // Primary wallet vault to transfer tokens to the secondary wallet
    #[account(mut)]
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
        space = 8 + 32 + 4 + (52 * (8 + 8 + 1)),   // Assuming approx. 52 plans (size calculation in comments)
        seeds = [b"plans", vesting_account.key().as_ref()],
        bump
    )]
    pub plan_chunk: Account<'info, VestingPlanChunk>,         // Create/update the target plan chunk

    #[account(mut)]
    pub parent_plan_chunk: Option<Account<'info, VestingPlanChunk>>, // Parent plan (optional)

    #[account(mut)]
    pub admin: Signer<'info>,                                  // Admin

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
        space = 8 + 4 + 32 + 4 + 10 + 8 + 32 + 32, // Approximate space calculation (including String length prefix)
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
    #[msg("No parent vesting plan found.")]
    ParentPlanNotFound,                           // Parent plan not found
    #[msg("Insufficient amount in the parent vesting plan.")]
    InsufficientAmount,                           // Insufficient amount in parent plan
    #[msg("Vesting for the specified time has already been completed.")]
    AlreadyReleased,                              // Already released for this time
    #[msg("Token not registered in token_info.")]
    InvalidToken,                                 // Unregistered token
    #[msg("Vault must be empty before closing the vesting account.")]
    VaultNotEmpty,                                // Vault must have a zero balance
    #[msg("Invalid Mint")]
    InvalidMint,                                  // Mint mismatch
}
