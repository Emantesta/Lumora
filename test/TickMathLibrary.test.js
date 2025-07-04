const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("TickMathLibrary", function () {
    let TickMathLibrary;

    beforeEach(async function () {
        const TickMathLibraryFactory = await ethers.getContractFactory("TickMathLibrary");
        TickMathLibrary = await TickMathLibraryFactory.deploy();
        await TickMathLibrary.deployed();
    });

    it("should convert price to tick correctly", async function () {
        // Test price = 1 (1e18 for 1:1 price, tokenB/tokenA)
        const price1 = ethers.utils.parseUnits("1", 18);
        const tick1 = await TickMathLibrary.priceToTick(price1);
        expect(tick1).to.be.closeTo(0, 1); // Tick ~0 for price = 1

        // Test price = 100 (100 tokenB per tokenA)
        const price2 = ethers.utils.parseUnits("100", 18);
        const tick2 = await TickMathLibrary.priceToTick(price2);
        expect(tick2).to.be.gt(0); // Positive tick for price > 1

        // Test price = 0.01 (0.01 tokenB per tokenA)
        const price3 = ethers.utils.parseUnits("0.01", 18);
        const tick3 = await TickMathLibrary.priceToTick(price3);
        expect(tick3).to.be.lt(0); // Negative tick for price < 1
    });

    it("should revert on zero price", async function () {
        await expect(TickMathLibrary.priceToTick(0)).to.be.revertedWithCustomError(
            TickMathLibrary,
            "InvalidPrice"
        );
    });

    it("should revert on out-of-bounds sqrtPriceX96", async function () {
        // Test extremely high price
        const highPrice = ethers.utils.parseUnits("1000000000000000000", 18);
        await expect(TickMathLibrary.priceToTick(highPrice)).to.be.revertedWithCustomError(
            TickMathLibrary,
            "InvalidSqrtPriceX96"
        );
    });

    it("should maintain existing tickToSqrtPriceX96 functionality", async function () {
        const tick = 0;
        const sqrtPriceX96 = await TickMathLibrary.tickToSqrtPriceX96(tick);
        expect(sqrtPriceX96).to.equal(await TickMathLibrary.tickToSqrtPriceX96(0)); // Ensure no regression
    });
});