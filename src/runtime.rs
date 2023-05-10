/// Command is the Transaction Kind that define how state mahcine transits.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum Command {
    /// Transfer Balance from transaction signer to recipient.
    Transfer {
        /// Recipient of the transfer
        recipient: PublicAddress,
        /// The amount to transfer
        amount: u64
    },

    /// Deploy smart contract to the state of the blockchain.
    Deploy {
        /// Smart contract in format of WASM bytecode
        contract: Vec<u8>,
        /// Version of Contract Binary Interface
        cbi_version: u32
    },

    /// Trigger method call of a deployed smart contract.
    Call {
        /// The address of the target contract
        target: PublicAddress,
        /// The method to be invoked
        method: String,
        /// The arguments supplied to the invoked method. It is a list of serialized method arguments (see [Serializable])
        arguments: Option<Vec<Vec<u8>>>,
        /// The amount sent to the target contract. The invoked contract can check the received amount 
        /// by host function `amount()` according to the CBI.
        amount: Option<u64>
    },

    /// Instantiation of a Pool in state
    CreatePool {
        /// Commission rate (in unit of percentage) is the portion that 
        /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
        commission_rate: u8
    },

    /// Update settings of an existing Pool.
    SetPoolSettings {
        /// Commission rate (in unit of percentage) is the portion that 
        /// the owners of its delegated stakes should pay from the reward in an epoch transaction.
        commission_rate: u8,
    },

    /// Delete an existing Pool in state.
    DeletePool,

    /// Instantiation of a Pool in state
    CreateDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The deposit amount
        balance: u64,
        /// Flag to indicate whether the received reward in epoch transaction should be automatically
        /// staked to the pool
        auto_stake_rewards: bool,
    },

    /// Update settings of an existing Deposit.
    SetDepositSettings {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// Flag to indicate whether the received reward in epoch transaction should be automatically
        /// staked to the pool
        auto_stake_rewards: bool,
    },

    /// Increase balance of an existing Deposit.
    TopUpDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount added to Deposit's Balance
        amount: u64,
    },

    /// Withdraw balance from an existing Deposit.
    WithdrawDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount of deposits that the stake owner wants to withdraw. The prefix 'max'
        /// is denoted here because the actual withdrawal amount can be less than 
        /// the wanted amount.
        max_amount: u64,
    },

    /// Increase stakes to an existing Pool
    StakeDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount of stakes that the stake owner wants to stake to the target pool. 
        /// The prefix 'max' is denoted here because the actual amount to be staked
        /// can be less than the wanted amount.
        max_amount: u64,
    },

    /// Remove stakes from an existing Pool.
    UnstakeDeposit {
        /// The address of operator of the target pool
        operator: PublicAddress,
        /// The amount of stakes that the stake owner wants to remove from the target pool. 
        /// The prefix 'max' is denoted here because the actual amount to be removed
        /// can be less than the wanted amount.
        max_amount: u64,
    },

    /// Administration Command: proceed to next epoch.
    NextEpoch,
}

impl Serializable for Command {}
impl Deserializable for Command {}
