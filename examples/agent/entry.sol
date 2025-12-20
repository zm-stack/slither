// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Contract {
    // ============ State Variables ============
    address public owner;
    uint256 public counter;
    mapping(address => uint256) public balances;

    // ============ Events ============
    event Received(address indexed from, uint256 amount);
    event FallbackCalled(address indexed from, uint256 amount);
    event CounterIncreased(uint256 newValue);
    event ExternalCallSuccess(bool success);

    // ============ Constructor ============
    constructor() {
        owner = msg.sender;
        counter = 0;
    }

    // ============ Modifiers ============
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ============ Receive Function ============
    receive() external payable {
        balances[msg.sender] += msg.value;
        emit Received(msg.sender, msg.value);
    }

    // ============ Fallback Function ============
    fallback() external payable {
        balances[msg.sender] += msg.value;
        emit FallbackCalled(msg.sender, msg.value);
    }

    // ============ Public User Functions ============
    /// Increase counter by 1
    function increment() public {
        counter += 1;
        emit CounterIncreased(counter);
    }

    /// Increase counter by a specific value
    function increment(uint256 value) public {
        counter += value;
        emit CounterIncreased(counter);
    }

    /// Decrease counter (calls internal function)
    function decrease(uint256 value) public {
        _decreaseInternal(value);
    }

    /// External call (to any contract)
    function callOther(address target, bytes calldata data) external {
        (bool success, ) = target.call(data);
        emit ExternalCallSuccess(success);
    }

    // ============ Payable User Function ============
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Received(msg.sender, msg.value);
    }

    // ============ Owner-Only Function ============
    function withdraw(uint256 amount) public onlyOwner {
        require(amount <= address(this).balance, "Insufficient balance");
        payable(owner).transfer(amount);
    }

    // ============ Internal Functions ============
    function _decreaseInternal(uint256 value) internal {
        require(counter >= value, "Underflow");
        counter -= value;
    }

    // ============ Private Helper Function ============
    function _double(uint256 x) private pure returns (uint256) {
        return x * 2;
    }

    /// Function that uses private helper
    function doubleCounter() public {
        counter = _double(counter);
    }
}
