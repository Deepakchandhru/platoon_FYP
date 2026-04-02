// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CATS {
    bytes32[] public commitments;

    struct VehicleData {
        uint256 capabilityScore;
        uint256 trustToken;
    }

    mapping(bytes32 => VehicleData) public vehicleData;

    // New structures for reputation and votes
    struct Reputation {
        int256 score;
        uint8 trustState; // 0: TRUSTED, 1: SUSPICIOUS, 2: MALICIOUS
        uint256 lastUpdated;
    }

    struct Vote {
        address voter;
        bytes32 targetCommitment;
        uint8 voteType; // 0: POSITIVE, 1: NEGATIVE
        uint256 timestamp;
        string reason;
    }

    struct Flag {
        bytes32 vehicleCommitment;
        string flagType;
        uint256 windowId;
        uint256 timestamp;
    }

    mapping(bytes32 => Reputation) public reputations;
    Vote[] public votes;
    Flag[] public flags;

    event ReputationUpdated(bytes32 indexed commitment, int256 score, uint8 trustState);
    event VoteRecorded(address indexed voter, bytes32 indexed target, uint8 voteType);
    event FlagAdded(bytes32 indexed vehicle, string flagType, uint256 windowId);

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

    // New functions for reputation
    function updateReputation(bytes32 _commitment, int256 _score, uint8 _trustState) public {
        reputations[_commitment] = Reputation(_score, _trustState, block.timestamp);
        emit ReputationUpdated(_commitment, _score, _trustState);
    }

    function getReputation(bytes32 _commitment) public view returns (int256, uint8, uint256) {
        Reputation memory rep = reputations[_commitment];
        return (rep.score, rep.trustState, rep.lastUpdated);
    }

    // New functions for votes
    function recordVote(bytes32 _targetCommitment, uint8 _voteType, string memory _reason) public {
        votes.push(Vote(msg.sender, _targetCommitment, _voteType, block.timestamp, _reason));
        emit VoteRecorded(msg.sender, _targetCommitment, _voteType);
    }

    function getVoteCount() public view returns (uint256) {
        return votes.length;
    }

    function getVote(uint256 _index) public view returns (address, bytes32, uint8, uint256, string memory) {
        Vote memory v = votes[_index];
        return (v.voter, v.targetCommitment, v.voteType, v.timestamp, v.reason);
    }

    // New functions for flags (optional anchor)
    function addFlag(bytes32 _vehicleCommitment, string memory _flagType, uint256 _windowId) public {
        flags.push(Flag(_vehicleCommitment, _flagType, _windowId, block.timestamp));
        emit FlagAdded(_vehicleCommitment, _flagType, _windowId);
    }

    function getFlagCount() public view returns (uint256) {
        return flags.length;
    }

    function getFlag(uint256 _index) public view returns (bytes32, string memory, uint256, uint256) {
        Flag memory f = flags[_index];
        return (f.vehicleCommitment, f.flagType, f.windowId, f.timestamp);
    }
}