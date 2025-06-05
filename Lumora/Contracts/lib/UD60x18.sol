// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

type UD60x18 is uint256;

library UD60x18 {
    function add(UD60x18 x, UD60x18 y) internal pure returns (UD60x18) {
        return UD60x18.wrap(UD60x18.unwrap(x) + UD60x18.unwrap(y));
    }
    function mul(UD60x18 x, UD60x18 y) internal pure returns (UD60x18) {
        return UD60x18.wrap(UD60x18.unwrap(x) * UD60x18.unwrap(y) / 1e18);
    }
    function div(UD60x18 x, UD60x18 y) internal pure returns (UD60x18) {
        require(UD60x18.unwrap(y) != 0, "UD60x18: division by zero");
        return UD60x18.wrap(UD60x18.unwrap(x) * 1e18 / UD60x18.unwrap(y));
    }
}
