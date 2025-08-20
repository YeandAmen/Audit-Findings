## High-1: Unrestricted NFT Minting by Users

Summary:
The requestMintWeatherNFT function allows users to mint an unlimited number of NFTs, enabling potential abuse and market manipulation through repeated minting and exploitation of incremental pricing logic.

Vulnerability Details:
The requestMintWeatherNFT function lacks restrictions on the number of NFTs a single address can mint, allowing users to repeatedly call the function, increase the mint price, and distort the NFT market.

Affected Code:
```solidity
function requestMintWeatherNFT(
    string memory _pincode,
    string memory _isoCode,
    bool _registerKeeper,
    uint256 _heartbeat,
    uint256 _initLinkDeposit
) external payable returns (bytes32 _reqId) {
    require(msg.value == s_currentMintPrice, WeatherNft__InvalidAmountSent());
    s_currentMintPrice += s_stepIncreasePerMint;
    if (_registerKeeper) {
        IERC20(s_link).safeTransferFrom(msg.sender, address(this), _initLinkDeposit);
    }
    _reqId = _sendFunctionsWeatherFetchRequest(_pincode, _isoCode);
    emit WeatherNFTMintRequestSent(msg.sender, _pincode, _isoCode, _reqId);
    s_funcReqIdToUserMintReq[_reqId] = UserMintRequest({
        user: msg.sender,
        pincode: _pincode,
        isoCode: _isoCode,
        registerKeeper: _registerKeeper,
        heartbeat: _heartbeat,
        initLinkDeposit: _initLinkDeposit
    });
}

Root Cause: Lack of per-user minting limit enforcement.
```
Attack Path:
User repeatedly calls requestMintWeatherNFT, paying the increasing s_currentMintPrice.
Each call increments s_currentMintPrice by s_stepIncreasePerMint.
User mints excessive NFTs, potentially flooding the market or manipulating prices.

Impact:
Market manipulation through excessive NFT minting.
Unfair price escalation for other users.
Potential for abuse to drain contract resources or LINK tokens.

Tools Used:
Manual review

Recommendations: Track user mint counts with a mapping and enforce a per-user mint cap:

 uint256 constant MAX_MINT_LIMIT = 5;
 mapping(address => uint256) public s_userMintCount;
```solidity
function requestMintWeatherNFT(
    string memory _pincode,
    string memory _isoCode,
    bool _registerKeeper,
    uint256 _heartbeat,
    uint256 _initLinkDeposit
) external payable returns (bytes32 _reqId) {
+   require(s_userMintCount[msg.sender] < MAX_MINT_LIMIT, "WeatherNft__MintLimitExceeded");
    require(msg.value == s_currentMintPrice, WeatherNft__InvalidAmountSent());
    s_currentMintPrice += s_stepIncreasePerMint;
+   s_userMintCount[msg.sender]++;
    // ... rest of the function
}
```





## High-2: Oracle Dependency Without Refund Mechanism

Summary:
The requestMintWeatherNFT function requires upfront payment but does not refund users if the oracle fails to fulfill the mint request, leading to potential fund loss.

Vulnerability Details:
Users pay the minting fee (s_currentMintPrice) when calling requestMintWeatherNFT. If the oracle fails to return a valid response, the contract retains the payment without minting an NFT.

Affected Code:
```solidity 
function requestMintWeatherNFT(
    string memory _pincode,
    string memory _isoCode,
    bool _registerKeeper,
    uint256 _heartbeat,
    uint256 _initLinkDeposit
) external payable returns (bytes32 _reqId) {
    require(msg.value == s_currentMintPrice, WeatherNft__InvalidAmountSent());
    s_currentMintPrice += s_stepIncreasePerMint;
    if (_registerKeeper) {
        IERC20(s_link).safeTransferFrom(msg.sender, address(this), _initLinkDeposit);
    }
    _reqId = _sendFunctionsWeatherFetchRequest(_pincode, _isoCode);
    emit WeatherNFTMintRequestSent(msg.sender, _pincode, _isoCode, _reqId);
    s_funcReqIdToUserMintReq[_reqId] = UserMintRequest({
        user: msg.sender,
        pincode: _pincode,
        isoCode: _isoCode,
        registerKeeper: _registerKeeper,
        heartbeat: _heartbeat,
        initLinkDeposit: _initLinkDeposit
    });
}
```
Root Cause: Absence of refund logic in case of oracle failure.

Attack Path:
User calls requestMintWeatherNFT and pays s_currentMintPrice.
Oracle fails to return a valid response (e.g, empty response or non-empty err).
Contract retains the payment without minting an NFT or refunding the user.

Impact:
Financial loss for users due to unrefunded payments.
Loss of trust in the NFT minting process.
Potential for repeated failed requests to drain user funds.

Tools Used:
Manual review

Recommendations: Implement refund logic in fulfillMintRequest and emit an event on failure:
```solidity 
function fulfillMintRequest(bytes32 requestId) external {
    bytes memory response = s_funcReqIdToMintFunctionReqResponse[requestId].response;
    bytes memory err = s_funcReqIdToMintFunctionReqResponse[requestId].err;
    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
    if (response.length == 0 || err.length > 0) {
+       UserMintRequest memory _userMintRequest = s_funcReqIdToUserMintReq[requestId];
+       payable(_userMintRequest.user).transfer(s_currentMintPrice);
+       emit WeatherNFTMintRequestFailed(requestId, _userMintRequest.user);
        return;
    }
    // ... rest of the function
}
```



## High-3: Unauthorized Fulfillment of Mint Requests

Summary:
The fulfillMintRequest function allows attackers to hijack NFT minting by calling it with a leaked requestId, minting NFTs to themselves without payment.

Vulnerability Details:
The function does not validate that the caller is the original minter, allowing anyone monitoring the WeatherNFTMintRequestSent event to front-run the fulfillment and mint the NFT to their address.

Affected Code:

```solidity
function fulfillMintRequest(bytes32 requestId) external {
    bytes memory response = s_funcReqIdToMintFunctionReqResponse[requestId].response;
    bytes memory err = s_funcReqIdToMintFunctionReqResponse[requestId].err;
    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
    if (response.length == 0 || err.length > 0) {
        return;
    }
    UserMintRequest memory _userMintRequest = s_funcReqIdToUserMintReq[requestId];
    uint8 weather = abi.decode(response, (uint8));
    uint256 tokenId = s_tokenCounter;
    s_tokenCounter++;
    emit WeatherNFTMinted(
        requestId,
        msg.sender, // Vulnerability: minted to attacker
        Weather(weather)
    );
    _mint(msg.sender, tokenId); // Vulnerability: no validation
    s_tokenIdToWeather[tokenId] = Weather(weather);
}
```
Root Cause: Missing validation of the caller against the original requester in s_funcReqIdToUserMintReq.

Attack Path:
User calls requestMintWeatherNFT, triggering WeatherNFTMintRequestSent with requestId.
Attacker monitors events and extracts requestId.
Attacker calls fulfillMintRequest(requestId) before the user.
NFT is minted to the attacker’s address instead of the user who paid.

Impact:
Loss of NFTs to unauthorized parties.
Financial loss for legitimate users who paid the minting fee.
Undermines the integrity of the minting process.

Tools Used:
Manual review
Event tracing

Recommendations: Enforce caller validation in fulfillMintRequest:
```solidity
function fulfillMintRequest(bytes32 requestId) external {
    bytes memory response = s_funcReqIdToMintFunctionReqResponse[requestId].response;
    bytes memory err = s_funcReqIdToMintFunctionReqResponse[requestId].err;
    require(response.length > 0 || err.length > 0, WeatherNft__Unauthorized());
+   UserMintRequest memory _userMintRequest = s_funcReqIdToUserMintReq[requestId];
+   require(msg.sender == _userMintRequest.user, "WeatherNft__UnauthorizedCaller");
    if (response.length == 0 || err.length > 0) {
        return;
    }
    // ... rest of the function
}
```



https://github.com/CodeHawks-Contests/2025-05-weather-witness/tree/e81df8689ab2b5e01d196bc5e5c82da84df5549a/src
