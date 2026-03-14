// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VehicleTrust {

    mapping(string => uint) public trustScore;

    function setTrustScore(string memory vehicleID, uint score) public {
        trustScore[vehicleID] = score;
    }

    function getTrustScore(string memory vehicleID) public view returns(uint){
        return trustScore[vehicleID];
    }
}