module test::vulnerable_contract {
    use std::signer;
    use aptos_framework::account;
    use aptos_framework::coin;
    use aptos_framework::timestamp;

    struct VulnerableContract has key {
        balance: u64,
        owner: address,
        last_withdrawal: u64,
        total_deposits: u64,
        user_balances: std::collections::Table<address, u64>,
    }

    // 1. Access Control Vulnerability
    public fun initialize(account: &signer) {
        let account_addr = signer::address_of(account);
        move_to(account, VulnerableContract {
            balance: 0,
            owner: account_addr,
            last_withdrawal: 0,
            total_deposits: 0,
            user_balances: std::collections::Table::new(),
        });
    }

    // 2. Reentrancy Vulnerability
    public fun withdraw(account: &signer, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No checks for amount
        contract.balance = contract.balance - amount;
        
        // External call before state update - vulnerable to reentrancy
        coin::transfer<aptos_coin::AptosCoin>(account, account_addr, amount);
        
        // State update after external call
        contract.last_withdrawal = timestamp::now_seconds();
    }

    // 3. Integer Overflow Vulnerability
    public fun add_balance(account: &signer, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No overflow check
        contract.balance = contract.balance + amount;
        contract.total_deposits = contract.total_deposits + amount;
    }

    // 4. Unchecked Arithmetic Vulnerability
    public fun unsafe_subtract(account: &signer, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No underflow check
        contract.balance = contract.balance - amount;
    }

    // 5. Missing Error Handling Vulnerability
    public fun divide(account: &signer, divisor: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No check for division by zero
        contract.balance = contract.balance / divisor;
    }

    // 6. Access Control Vulnerability (State Modification)
    public fun change_owner(account: &signer, new_owner: address) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No check if caller is owner
        contract.owner = new_owner;
    }

    // 7. Access Control Vulnerability (User Balance)
    public fun update_user_balance(account: &signer, user: address, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No access control check
        std::collections::Table::add(&mut contract.user_balances, user, amount);
    }

    // 8. Integer Overflow in User Balance
    public fun add_user_balance(account: &signer, user: address, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No overflow check for user balance
        let current_balance = std::collections::Table::borrow(&contract.user_balances, user);
        std::collections::Table::add(&mut contract.user_balances, user, *current_balance + amount);
    }

    // 9. Missing Error Handling in User Operations
    public fun transfer_user_balance(account: &signer, from: address, to: address, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // No checks for user existence or sufficient balance
        let from_balance = std::collections::Table::borrow(&contract.user_balances, from);
        let to_balance = std::collections::Table::borrow(&contract.user_balances, to);
        
        std::collections::Table::add(&mut contract.user_balances, from, *from_balance - amount);
        std::collections::Table::add(&mut contract.user_balances, to, *to_balance + amount);
    }

    // 10. Reentrancy Vulnerability in User Operations
    public fun withdraw_user_balance(account: &signer, amount: u64) {
        let account_addr = signer::address_of(account);
        let contract = borrow_global_mut<VulnerableContract>(account_addr);
        
        // External call before state update
        coin::transfer<aptos_coin::AptosCoin>(account, account_addr, amount);
        
        // State update after external call
        let user_balance = std::collections::Table::borrow(&contract.user_balances, account_addr);
        std::collections::Table::add(&mut contract.user_balances, account_addr, *user_balance - amount);
    }
} 