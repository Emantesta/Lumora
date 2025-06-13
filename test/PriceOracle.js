const PriceOracle = artifacts.require("PriceOracle");
const { expectRevert } = require("@openzeppelin/test-helpers");

contract("PriceOracle", accounts => {
    let oracle;
    const [owner, newOwner] = accounts;

    beforeEach(async () => {
        oracle = await PriceOracle.new("0xYourVRFCoordinatorAddress");
        await oracle.initialize(
            owner,
            "0xYourVRFCoordinatorAddress",
            1234, // subscriptionId
            "0xYourKeyHash",
            100000, // callbackGasLimit
            3 // requestConfirmations
        );
    });

    it("should transfer ownership", async () => {
        await oracle.transferOwnership(newOwner, { from: owner });
        assert.equal(await oracle.owner(), newOwner, "Ownership not transferred");
    });

    it("should revert proposeOwner", async () => {
        await expectRevert(
            oracle.proposeOwner(newOwner, { from: owner }),
            "Propose owner not supported; use transferOwnership instead"
        );
    });
});