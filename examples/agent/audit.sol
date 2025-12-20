// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ComplexBank {
    address public owner;
    address public admin;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
        admin = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function deposit() external payable {
        updateBalance(msg.sender, msg.value);
    }

    function updateBalance(address user, uint amount) internal {
        balances[user] += amount;
    }

    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        _withdrawInternal(msg.sender, amount);
        
        balances[msg.sender] -= amount;
    }

    function _withdrawInternal(address to, uint amount) internal {
        safeTransfer(to, amount);
    }

    function safeTransfer(address to, uint amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function adminWithdraw(address user, uint amount) external onlyAdmin {
        withdrawAll(user, amount);
    }

    function withdrawAll(address user, uint amount) internal {
        _unsafeLowLevelCall(user, amount);
    }

    function _unsafeLowLevelCall(address target, uint amount) internal {
        target.call{value: amount}("arbitrary payload");
    }

    function setAdmin(address newAdmin) external onlyOwner {
        admin = newAdmin;
    }
}
