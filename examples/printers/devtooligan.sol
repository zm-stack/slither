pragma solidity ^0.8.18;

contract BContract1{
    function a() public pure {}
}

contract BContract2{
    function b() public pure {}
}

contract CContract1 {
    modifier auth {_;}
    BContract1 public bc;
    BContract2 public bc2;
    constructor() {
        bc = new BContract1();
        bc2 = new BContract2();
    }
    function c() public auth {
        _c();
    }

    function _c() internal view {
        bc.a();
        bc2.b();
        bc2.b();
    }
}

