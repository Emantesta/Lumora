// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Initializable.sol";

abstract contract UUPSUpgradeable is Initializable {
    address private immutable __self = address(this);

    modifier onlyProxy() {
        require(address(this) != __self, "Function must be called through delegatecall");
        require(_getImplementation() == __self, "Function must be called through active proxy");
        _;
    }

    function _authorizeUpgrade(address newImplementation) internal virtual;

    function _getImplementation() internal view returns (address) {
        return address(this);
    }

    function upgradeTo(address newImplementation) public onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeTo(newImplementation);
    }

    function _upgradeTo(address newImplementation) internal {
        require(newImplementation != address(0), "UUPSUpgradeable: new implementation is zero address");
        assembly {
            sstore(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, newImplementation)
        }
    }
}
