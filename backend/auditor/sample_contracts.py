"""
Sample vulnerable and safe contracts for testing and demo purposes.
"""

SAMPLE_CONTRACTS = {
    "reentrancy_vulnerable": {
        "name": "Reentrancy Vulnerable",
        "description": "Classic reentrancy attack — external call before state update",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update AFTER call — reentrancy possible!
        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}""",
    },
    "access_control_flaw": {
        "name": "Access Control Flaw",
        "description": "Missing access control on critical functions",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnsafeVault {
    address public owner;
    mapping(address => uint256) public deposits;
    
    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    // VULNERABLE: No access control!
    function withdrawAll(address payable to) external {
        // Anyone can call this and drain all funds
        uint256 balance = address(this).balance;
        (bool success, ) = to.call{value: balance}("");
        require(success);
    }

    // VULNERABLE: Uses tx.origin instead of msg.sender
    function changeOwner(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    // VULNERABLE: No access control on selfdestruct
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}""",
    },
    "multiple_vulnerabilities": {
        "name": "Multiple Vulnerabilities",
        "description": "Contract with several different vulnerability types",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuctionHouse {
    address public highestBidder;
    uint256 public highestBid;
    address public owner;
    mapping(address => uint256) public pendingReturns;
    bool public ended;

    // ISSUE: Floating pragma
    // ISSUE: No events defined

    constructor() {
        owner = msg.sender;
    }

    function bid() external payable {
        // VULNERABLE: Timestamp dependency
        require(block.timestamp < 1700000000, "Auction ended");
        require(msg.value > highestBid, "Bid too low");

        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0);
        
        // VULNERABLE: Reentrancy — call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        pendingReturns[msg.sender] = 0;
    }

    function endAuction() external {
        // VULNERABLE: No access control
        ended = true;
        
        // VULNERABLE: Using send without checking return
        payable(owner).send(address(this).balance);
    }

    // VULNERABLE: delegatecall to user-supplied address
    function execute(address target, bytes calldata data) external {
        (bool success, ) = target.delegatecall(data);
        require(success);
    }
}""",
    },
    "safe_contract": {
        "name": "Safe Contract (OpenZeppelin)",
        "description": "Well-secured contract using OpenZeppelin standards",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureVault is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() Ownable() {}

    function deposit() external payable {
        require(msg.value > 0, "Must deposit > 0");
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Checks-Effects-Interactions pattern
        balances[msg.sender] -= amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(msg.sender, amount);
    }

    function emergencyWithdraw() external onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = owner().call{value: balance}("");
        require(success, "Transfer failed");
    }
}""",
    },
    "defi_vulnerable": {
        "name": "DeFi Lending Vulnerable",
        "description": "Simplified lending protocol with flash loan vulnerability",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleLender {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    uint256 public totalDeposits;
    uint256 public totalBorrows;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // VULNERABLE: No collateral check
    function borrow(uint256 amount) external {
        require(amount <= totalDeposits - totalBorrows, "Not enough liquidity");
        
        borrows[msg.sender] += amount;
        totalBorrows += amount;

        // VULNERABLE: Reentrancy
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        // State already updated above, but external call is risky
    }

    function repay() external payable {
        require(borrows[msg.sender] >= msg.value, "Overpaying");
        borrows[msg.sender] -= msg.value;
        totalBorrows -= msg.value;
    }

    // VULNERABLE: No access control, price manipulation possible
    function liquidate(address borrower) external {
        uint256 debt = borrows[borrower];
        uint256 collateral = deposits[borrower];
        
        // VULNERABLE: No oracle, no health factor check
        borrows[borrower] = 0;
        deposits[borrower] = 0;
        
        (bool success, ) = msg.sender.call{value: collateral}("");
        require(success);
    }
}""",
    },
}

# All sample codes for quick access
SAMPLE_LIST = [
    {"id": key, "name": val["name"], "description": val["description"]}
    for key, val in SAMPLE_CONTRACTS.items()
]
