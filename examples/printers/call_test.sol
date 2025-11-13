// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 一个简单的 Library
library MathLib {
    function add(uint a, uint b) external pure returns (uint) {
        return a + b;
    }
}

// 主合约
contract Contract {

    uint public stateVar; // Solidity 高级调用（getter）

    // internal 调用示例
    function foo(uint x) public {
        bar(x); // internal
    }

    function bar(uint y) internal {
        stateVar = y;
    }

    // library 调用
    function addWithLibrary(uint a, uint b) public {
        uint c = MathLib.add(a, b); // library call
        baz(c);
    }

    // high-level 调用（通过接口或 public function）
    function baz(uint z) public {
        stateVar = z;
        qux(); // high-level call to public function
    }

    function qux() public {
        stateVar = stateVar + 1;
    }

    // low-level 调用
    function callExternal(address target) public {
        // low-level call
        (bool success, ) = target.call(abi.encodeWithSignature("qux()"));
        require(success, "call failed");
    }
}
