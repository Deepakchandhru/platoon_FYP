// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MerkleCommitment {
    bytes32[] public commitments;

    struct VehicleData {
        uint256 capabilityScore;
        uint256 trustToken;
    }

    mapping(bytes32 => VehicleData) public vehicleData;

    function addCommitment(bytes32 _commitment, uint256 _capabilityScore, uint256 _trustToken) public {
        vehicleData[_commitment] = VehicleData(_capabilityScore, _trustToken);
        commitments.push(_commitment);
    }

    function getCommitments() public view returns (bytes32[] memory) {
        return commitments;
    }

    function getCommitmentCount() public view returns (uint256) {
        return commitments.length;
    }

    function getVehicleData(bytes32 _commitment) public view returns (uint256, uint256) {
        return (vehicleData[_commitment].capabilityScore, vehicleData[_commitment].trustToken);
    }
}