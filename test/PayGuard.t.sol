// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;
import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {PayGuard} from "../src/PayGuard.sol";

contract USDCMock is ERC20 { constructor() ERC20("USDC", "USDC") {} function decimals() public pure override returns (uint8) { return 6; } function mint(address to, uint256 a) external { _mint(to, a); } }

contract PayGuardTest is Test {
    PayGuard g; USDCMock usdc; uint256 attPk = 0xA11CE; address att; address payer = address(0xBEEF); address payee = address(0xCAFE); address mallory = address(0xBAD);
    function setUp() public {
        vm.chainId(5042); vm.warp(1_800_000_000);
        att = vm.addr(attPk); usdc = new USDCMock(); g = new PayGuard(att, address(usdc));
        usdc.mint(payer, 1_000e6); vm.prank(payer); usdc.approve(address(g), type(uint256).max);
    }
    function _v(uint8 verdict, uint256 maxAmt, uint64 exp, address p, address to) internal view returns (PayGuard.Verdict memory v) {
        v = PayGuard.Verdict(p, to, maxAmt, verdict, 0, 29_000_000, uint64(block.timestamp), exp, keccak256("[]"));
    }
    function _sig(PayGuard.Verdict memory v, uint256 pk) internal view returns (bytes memory) { (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, g.digest(v)); return abi.encodePacked(r, s, vv); }
    function testDomainMatchesApi() public view {
        bytes32 want = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,uint256 chainId)"), keccak256("APEX PayeeCheck"), keccak256("1"), uint256(5042)));
        assertEq(g.DOMAIN_SEPARATOR(), want);
    }
    function testCleanVerdictPays() public {
        PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee);
        bytes memory s = _sig(v, attPk); vm.prank(payer); g.pay(v, s, 100e6, "invoice 17");
        assertEq(usdc.balanceOf(payee), 100e6); assertEq(usdc.balanceOf(payer), 900e6); assertEq(usdc.balanceOf(address(g)), 0);
    }
    function testCautionRefused() public { PayGuard.Verdict memory v = _v(1, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk); vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(PayGuard.NotClean.selector, uint8(1))); g.pay(v, s, 1e6, ""); }
    function testDoNotPayRefused() public { PayGuard.Verdict memory v = _v(2, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk); vm.prank(payer); vm.expectRevert(abi.encodeWithSelector(PayGuard.NotClean.selector, uint8(2))); g.pay(v, s, 1e6, ""); }
    function testExpiredRefused() public { PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk); vm.warp(block.timestamp + 601); vm.prank(payer); vm.expectRevert(PayGuard.Expired.selector); g.pay(v, s, 1e6, ""); }
    function testOtherCallerCannotUseVerdict() public {   // mallory holds a verdict for payer: she cannot spend payer's allowance
        PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, mallory); bytes memory s = _sig(v, attPk);
        vm.prank(mallory); vm.expectRevert(PayGuard.WrongPayer.selector); g.pay(v, s, 100e6, "");
    }
    function testNoCapRefused() public { PayGuard.Verdict memory v = _v(0, 0, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk); vm.prank(payer); vm.expectRevert(PayGuard.NoAmountCap.selector); g.pay(v, s, 1e6, ""); }
    function testOverMaxRefused() public { PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk); vm.prank(payer); vm.expectRevert(PayGuard.OverMax.selector); g.pay(v, s, 250e6 + 1, ""); }
    function testForeignSignerRefused() public { PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, 0xB0B); vm.prank(payer); vm.expectRevert(PayGuard.BadSignature.selector); g.pay(v, s, 1e6, ""); }
    function testTamperedPayeeRefused() public {   // a clean verdict for payee cannot be pointed at another address
        PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk); v.payee = mallory;
        vm.prank(payer); vm.expectRevert(PayGuard.BadSignature.selector); g.pay(v, s, 1e6, "");
    }
    function testReplayRefused() public {
        PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk);
        vm.startPrank(payer); g.pay(v, s, 10e6, ""); vm.expectRevert(PayGuard.Replayed.selector); g.pay(v, s, 10e6, ""); vm.stopPrank();
    }
    function testFuzzAmountCap(uint256 amt) public {
        amt = bound(amt, 1, 1_000e6); PayGuard.Verdict memory v = _v(0, 250e6, uint64(block.timestamp + 600), payer, payee); bytes memory s = _sig(v, attPk);
        vm.prank(payer);
        if (amt > 250e6) { vm.expectRevert(PayGuard.OverMax.selector); g.pay(v, s, amt, ""); } else { g.pay(v, s, amt, ""); assertEq(usdc.balanceOf(payee), amt); }
    }
}
