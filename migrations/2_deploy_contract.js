const AadhaarRegistry  = artifacts.require("AadhaarRegistry");
const PassportRegistry = artifacts.require("PassportRegistry");

module.exports = function(deployer) {
  deployer.deploy(AadhaarRegistry);
  deployer.deploy(PassportRegistry);
};