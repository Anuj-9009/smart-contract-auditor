"""
Test suite for Smart Contract Auditor v2 (zero-cost engine).
Run: cd backend && source venv/bin/activate && pytest tests/test_engine.py -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from auditor.engine import SmartContractAuditor, PatternAnalyzer

# ─── Test Contracts ──────────────────────────────────────────

REENTRANCY = """
pragma solidity ^0.8.0;
contract ReentrancyVuln {
    mapping(address => uint) balance;
    function withdraw() external {
        uint amount = balance[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balance[msg.sender] = 0;
    }
}
"""

TX_ORIGIN = """
pragma solidity ^0.8.0;
contract TxOriginVuln {
    address owner;
    constructor() { owner = msg.sender; }
    function changeOwner(address newOwner) external {
        require(tx.origin == owner);
        owner = newOwner;
    }
}
"""

SELFDESTRUCT = """
pragma solidity ^0.8.0;
contract Destroyable {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
"""

TIMESTAMP = """
pragma solidity ^0.8.0;
contract TimeLock {
    function isLucky() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }
}
"""

SAFE = """
pragma solidity 0.8.19;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
contract Safe is ReentrancyGuard, Ownable {
    mapping(address => uint) balance;
    function withdraw() external nonReentrant {
        uint amount = balance[msg.sender];
        balance[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
"""

# ─── Pattern Analyzer Tests ─────────────────────────────────

class TestPatternAnalyzer:
    def setup_method(self):
        self.pa = PatternAnalyzer()

    def test_reentrancy(self):
        r = self.pa.analyze(REENTRANCY)
        assert any(v["type"] == "reentrancy" for v in r)

    def test_tx_origin(self):
        r = self.pa.analyze(TX_ORIGIN)
        assert any(v["type"] == "tx_origin_auth" for v in r)

    def test_selfdestruct(self):
        r = self.pa.analyze(SELFDESTRUCT)
        assert any(v["type"] == "unprotected_selfdestruct" for v in r)

    def test_timestamp(self):
        r = self.pa.analyze(TIMESTAMP)
        assert any(v["type"] == "timestamp_dependency" for v in r)

    def test_floating_pragma(self):
        r = self.pa.analyze(REENTRANCY)
        assert any(v["type"] == "floating_pragma" for v in r)

    def test_safe_no_reentrancy(self):
        r = self.pa.analyze(SAFE)
        assert not any(v["type"] == "reentrancy" for v in r)

    def test_safe_no_floating_pragma(self):
        r = self.pa.analyze(SAFE)
        assert not any(v["type"] == "floating_pragma" for v in r)

    def test_standards_check(self):
        stds = self.pa.get_standards_check(SAFE)
        assert "Reentrancy Protection" in stds
        assert "Ownership Pattern" in stds


# ─── Full Auditor Tests (pattern-only, no LLM) ──────────────

class TestAuditor:
    def setup_method(self):
        self.auditor = SmartContractAuditor()

    def test_reentrancy_detected(self):
        r = self.auditor.audit_contract(REENTRANCY, mode="quick")
        assert r["status"] == "success"
        assert r["critical_count"] > 0

    def test_safe_contract(self):
        r = self.auditor.audit_contract(SAFE, mode="quick")
        assert r["status"] == "success"
        assert r["critical_count"] == 0

    def test_risk_score(self):
        r = self.auditor.audit_contract(REENTRANCY, mode="quick")
        assert r["risk_score"] > 0

    def test_report(self):
        r = self.auditor.audit_contract(REENTRANCY, mode="quick")
        report = self.auditor.generate_report(r)
        assert "AUDIT REPORT" in report

    def test_empty(self):
        r = self.auditor.audit_contract("", mode="quick")
        assert r["total_found"] == 0

    def test_provider_info(self):
        r = self.auditor.audit_contract(REENTRANCY, mode="quick")
        assert "llm_provider" in r


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
