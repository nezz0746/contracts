// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.11;

/// @author thirdweb

import "./DirectListingsStorage.sol";

// ====== External imports ======
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "../../../eip/interface/IERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC2981.sol";

// ====== Internal imports ======

import "../../../extension/interface/IPlatformFee.sol";
import "../../../extension/upgradeable/ERC2771ContextConsumer.sol";
import "../../../extension/upgradeable/ReentrancyGuard.sol";
import "../../../extension/upgradeable/PermissionsEnumerable.sol";
import { RoyaltyPaymentsLogic } from "../../../extension/upgradeable/RoyaltyPayments.sol";
import { CurrencyTransferLib } from "../../../lib/CurrencyTransferLib.sol";
import { ISuperToken } from "@superfluid-finance/ethereum-contracts/contracts/interfaces/superfluid/ISuperfluid.sol";
import { SuperTokenV1Library } from "@superfluid-finance/ethereum-contracts/contracts/apps/SuperTokenV1Library.sol";
import { console } from "forge-std/Test.sol";

/**
 * @author  thirdweb.com
 */
contract DirectListingsLogic is IDirectListings, ReentrancyGuard, ERC2771ContextConsumer {
    using SuperTokenV1Library for ISuperToken;

    mapping(address => address) public tokenXs;

    /*///////////////////////////////////////////////////////////////
                        Constants / Immutables
    //////////////////////////////////////////////////////////////*/

    /// @dev Only lister role holders can create listings, when listings are restricted by lister address.
    bytes32 private constant LISTER_ROLE = keccak256("LISTER_ROLE");
    /// @dev Only assets from NFT contracts with asset role can be listed, when listings are restricted by asset address.
    bytes32 private constant ASSET_ROLE = keccak256("ASSET_ROLE");
    /// @dev Only tax manager role holders can set allowed currencies for tax
    bytes32 private constant TAX_MANAGER_ROLE = keccak256("TAX_MANAGER_ROLE");
    /// @dev Only landlord role holders can foreclose listings
    bytes32 private constant LANDLORD_ROLE = keccak256("LANDLORD_ROLE");

    /// @dev The max bps of the contract. So, 10_000 == 100 %
    uint64 private constant MAX_BPS = 10_000;

    /// @dev The address of the native token wrapper contract.
    address private immutable nativeTokenWrapper;

    event TokenXSet(address indexed underlyingToken, address indexed superToken);

    /*///////////////////////////////////////////////////////////////
                            Modifier
    //////////////////////////////////////////////////////////////*/

    /// @dev Checks whether the caller has LISTER_ROLE.
    modifier onlyListerRole() {
        require(Permissions(address(this)).hasRoleWithSwitch(LISTER_ROLE, _msgSender()), "!LISTER_ROLE");
        _;
    }

    /// @dev Checks whether the caller has ASSET_ROLE.
    modifier onlyAssetRole(address _asset) {
        // Modified: Only allowing ERC721 tokens to be listed
        require(_getTokenType(_asset) == TokenType.ERC721, "Marketplace: listed token must be ERC721.");
        require(Permissions(address(this)).hasRoleWithSwitch(ASSET_ROLE, _asset), "!ASSET_ROLE");
        _;
    }

    /// @dev Checks whether the caller has TAX_MANAGER_ROLE.
    modifier onlyTaxManagerRole() {
        require(Permissions(address(this)).hasRoleWithSwitch(TAX_MANAGER_ROLE, _msgSender()), "!TAX_MANAGER_ROLE");
        _;
    }

    /// @dev Checks whether caller is a listing creator.
    /// Modified: Changed the listing creator to the current owner of the NFT
    modifier onlyCurrentListingNFTOwner(uint256 _listingId) {
        require(
            _currentListingNFTOwner(_directListingsStorage().listings[_listingId]) == _msgSender(),
            "Marketplace: not listing creator."
        );
        _;
    }

    /// @dev Checks whether a listing exists.
    modifier onlyExistingListing(uint256 _listingId) {
        require(
            _directListingsStorage().listings[_listingId].status == IDirectListings.Status.CREATED,
            "Marketplace: invalid listing."
        );
        _;
    }

    /*///////////////////////////////////////////////////////////////
                            Constructor logic
    //////////////////////////////////////////////////////////////*/

    constructor(address _nativeTokenWrapper) {
        nativeTokenWrapper = _nativeTokenWrapper;
    }

    /*///////////////////////////////////////////////////////////////
                            External functions
    //////////////////////////////////////////////////////////////*/

    // Modified: Only allowing ERC721 tokens to be listed
    /// @notice List NFTs (ERC721 or ERC1155) for sale at a fixed price.
    function createListing(
        ListingParameters calldata _params
    ) external onlyListerRole onlyAssetRole(_params.assetContract) returns (uint256 listingId) {
        listingId = _getNextListingId();
        address listingCreator = _ownerOfERC721(_params.assetContract, _params.tokenId);

        require(listingCreator == _msgSender(), "Marketplace: not owner of token.");
        require(tokenXs[_params.currency] != address(0), "Marketplace: invalid currency");

        TokenType tokenType = _getTokenType(_params.assetContract);

        uint128 startTime = _params.startTimestamp;
        uint128 endTime = _params.endTimestamp;
        require(startTime < endTime, "Marketplace: endTimestamp not greater than startTimestamp.");
        if (startTime < block.timestamp) {
            require(startTime + 60 minutes >= block.timestamp, "Marketplace: invalid startTimestamp.");

            startTime = uint128(block.timestamp);
            endTime = endTime == type(uint128).max
                ? endTime
                : startTime + (_params.endTimestamp - _params.startTimestamp);
        }

        _validateNewListing(_params, tokenType);

        Listing memory listing = Listing({
            listingId: listingId,
            // Modified: concept of listingCreator replaced with current listing nft owner
            listingCreator: address(0),
            listingOwner: _params.taxBeneficiary,
            assetContract: _params.assetContract,
            tokenId: _params.tokenId,
            quantity: _params.quantity,
            currency: _params.currency,
            taxRate: _params.taxRate,
            taxBeneficiary: _params.taxBeneficiary,
            pricePerToken: _params.pricePerToken,
            startTimestamp: startTime,
            endTimestamp: type(uint128).max,
            reserved: _params.reserved,
            tokenType: tokenType,
            status: IDirectListings.Status.CREATED
        });

        _directListingsStorage().listings[listingId] = listing;

        emit NewListing(address(0), listingId, _params.assetContract, listing);
    }

    /// @notice Update parameters of a listing of NFTs.
    function updateListing(
        uint256 _listingId,
        ListingParameters memory _params
    )
        external
        onlyExistingListing(_listingId)
        onlyAssetRole(_params.assetContract)
        onlyCurrentListingNFTOwner(_listingId)
    {
        address listingCreator = _ownerOfERC721(_params.assetContract, _params.tokenId);

        require(listingCreator == _msgSender(), "Marketplace: not owner of token.");

        Listing memory listing = _directListingsStorage().listings[_listingId];
        TokenType tokenType = _getTokenType(_params.assetContract);

        require(listing.endTimestamp > block.timestamp, "Marketplace: listing expired.");

        require(
            listing.assetContract == _params.assetContract && listing.tokenId == _params.tokenId,
            "Marketplace: cannot update what token is listed."
        );

        uint128 startTime = _params.startTimestamp;
        uint128 endTime = _params.endTimestamp;
        require(startTime < endTime, "Marketplace: endTimestamp not greater than startTimestamp.");
        require(
            listing.startTimestamp > block.timestamp ||
                (startTime == listing.startTimestamp && endTime > block.timestamp),
            "Marketplace: listing already active."
        );
        if (startTime != listing.startTimestamp && startTime < block.timestamp) {
            require(startTime + 60 minutes >= block.timestamp, "Marketplace: invalid startTimestamp.");

            startTime = uint128(block.timestamp);

            endTime = endTime == listing.endTimestamp || endTime == type(uint128).max
                ? endTime
                : startTime + (_params.endTimestamp - _params.startTimestamp);
        }

        {
            uint256 _approvedCurrencyPrice = _directListingsStorage().currencyPriceForListing[_listingId][
                _params.currency
            ];
            require(
                _approvedCurrencyPrice == 0 || _params.pricePerToken == _approvedCurrencyPrice,
                "Marketplace: price different from approved price"
            );
        }

        _validateNewListing(_params, tokenType);

        // Get total flowRate to beneficiary
        (, int96 totalFlowRate, , ) = ISuperToken(tokenXs[listing.currency]).getFlowInfo(
            listingCreator,
            listing.taxBeneficiary
        );
        // Get current listing flowRate
        int96 listingFlowRate = _getFlowRate(listing.taxRate, listing.pricePerToken);

        listing = Listing({
            listingId: _listingId,
            listingCreator: listingCreator,
            listingOwner: listing.listingOwner,
            assetContract: listing.assetContract,
            tokenId: listing.tokenId,
            quantity: listing.quantity,
            currency: listing.currency,
            taxRate: listing.taxRate,
            taxBeneficiary: listing.taxBeneficiary,
            // Modified: only let owner update the price
            pricePerToken: _params.pricePerToken,
            startTimestamp: startTime,
            endTimestamp: type(uint128).max,
            reserved: listing.reserved,
            tokenType: tokenType,
            status: IDirectListings.Status.CREATED
        });

        _directListingsStorage().listings[_listingId] = listing;

        // Get new listing flowRate
        int96 newListingFlowRate = _getFlowRate(listing.taxRate, listing.pricePerToken);

        // Update stream flow of listing creator
        if (totalFlowRate > 0 && listingCreator != listing.taxBeneficiary) {
            if (newListingFlowRate > listingFlowRate) {
                _updateStream(
                    listing.currency,
                    listingCreator,
                    listing.taxBeneficiary,
                    totalFlowRate + newListingFlowRate - listingFlowRate
                );
            } else {
                _updateStream(
                    listing.currency,
                    listingCreator,
                    listing.taxBeneficiary,
                    totalFlowRate - listingFlowRate + newListingFlowRate
                );
            }
        }

        emit UpdatedListing(listingCreator, _listingId, listing.assetContract, listing);
    }

    /// @notice Cancel a listing. Cancelling the perpetual listing means giving up ownership of the NFT
    /// and sending back to the beneficiary. Stream is also cancelled.
    function cancelListing(
        uint256 _listingId
    ) external onlyExistingListing(_listingId) onlyCurrentListingNFTOwner(_listingId) {
        Listing memory listing = _directListingsStorage().listings[_listingId];

        address listingOwner = _currentListingNFTOwner(listing);
        // Get total flowRate to beneficiary
        (, int96 totalFlowRate, , ) = ISuperToken(tokenXs[listing.currency]).getFlowInfo(
            listingOwner,
            listing.taxBeneficiary
        );
        int96 listingFlowRate = _getFlowRate(listing.taxRate, listing.pricePerToken);

        if (totalFlowRate > listingFlowRate)
            _updateStream(listing.currency, listingOwner, listing.taxBeneficiary, totalFlowRate - listingFlowRate);
        else _cancelStream(listing.currency, listingOwner, listing.taxBeneficiary);

        _transferListingTokens(listingOwner, listing.taxBeneficiary, listing.quantity, listing);

        emit CancelledListing(_msgSender(), _listingId);
    }

    function forecloseListing(uint256 _listingId) external onlyExistingListing(_listingId) {
        Listing memory listing = _directListingsStorage().listings[_listingId];

        require(
            _msgSender() == listing.taxBeneficiary ||
                Permissions(address(this)).hasRoleWithSwitch(LANDLORD_ROLE, _msgSender()),
            "Marketplace: not tax beneficiary or landlord"
        );

        require(
            ISuperToken(tokenXs[listing.currency]).balanceOf(_currentListingNFTOwner(listing)) == 0,
            "Marketplace: current listing owner has balance"
        );

        address listingOwner = _currentListingNFTOwner(listing);
        // Get total flowRate to beneficiary
        (, int96 totalFlowRate, , ) = ISuperToken(tokenXs[listing.currency]).getFlowInfo(
            listingOwner,
            listing.taxBeneficiary
        );
        int96 listingFlowRate = _getFlowRate(listing.taxRate, listing.pricePerToken);

        if (totalFlowRate > listingFlowRate)
            _updateStream(listing.currency, listingOwner, listing.taxBeneficiary, totalFlowRate - listingFlowRate);
        else _cancelStream(listing.currency, listingOwner, listing.taxBeneficiary);

        _transferListingTokens(listingOwner, listing.taxBeneficiary, listing.quantity, listing);
    }

    /// @notice Approve a buyer to buy from a reserved listing.
    function approveBuyerForListing(
        uint256 _listingId,
        address _buyer,
        bool _toApprove
    ) external onlyExistingListing(_listingId) onlyCurrentListingNFTOwner(_listingId) {
        require(_directListingsStorage().listings[_listingId].reserved, "Marketplace: listing not reserved.");

        _directListingsStorage().isBuyerApprovedForListing[_listingId][_buyer] = _toApprove;

        emit BuyerApprovedForListing(_listingId, _buyer, _toApprove);
    }

    /// @notice Approve a currency as a form of payment for the listing.
    function approveCurrencyForListing(
        uint256 _listingId,
        address _currency,
        uint256 _pricePerTokenInCurrency
    ) external onlyExistingListing(_listingId) onlyCurrentListingNFTOwner(_listingId) {
        Listing memory listing = _directListingsStorage().listings[_listingId];
        require(
            _currency != listing.currency || _pricePerTokenInCurrency == listing.pricePerToken,
            "Marketplace: approving listing currency with different price."
        );
        require(
            _directListingsStorage().currencyPriceForListing[_listingId][_currency] != _pricePerTokenInCurrency,
            "Marketplace: price unchanged."
        );

        _directListingsStorage().currencyPriceForListing[_listingId][_currency] = _pricePerTokenInCurrency;

        emit CurrencyApprovedForListing(_listingId, _currency, _pricePerTokenInCurrency);
    }

    /// @notice Buy NFTs from a listing.
    function buyFromListing(
        uint256 _listingId,
        address _buyFor,
        uint256 _quantity,
        address _currency,
        uint256 _expectedTotalPrice
    ) external payable nonReentrant onlyExistingListing(_listingId) {
        Listing memory listing = _directListingsStorage().listings[_listingId];
        address buyer = _msgSender();

        require(_buyFor == buyer, "Marketplace: msg.sender must be the buyer.");
        require(_buyFor != _currentListingNFTOwner(listing), "Marketplace: cannot buy from self.");
        require(
            !listing.reserved || _directListingsStorage().isBuyerApprovedForListing[_listingId][buyer],
            "buyer not approved"
        );
        require(_quantity > 0 && _quantity <= listing.quantity, "Buying invalid quantity");
        require(
            block.timestamp < listing.endTimestamp && block.timestamp >= listing.startTimestamp,
            "not within sale window."
        );

        require(
            _validateOwnershipAndApproval(
                _currentListingNFTOwner(listing),
                listing.assetContract,
                listing.tokenId,
                _quantity,
                listing.tokenType
            ),
            "Marketplace: not owner or approved tokens."
        );

        uint256 targetTotalPrice;

        if (_directListingsStorage().currencyPriceForListing[_listingId][_currency] > 0) {
            targetTotalPrice = _quantity * _directListingsStorage().currencyPriceForListing[_listingId][_currency];
        } else {
            require(_currency == listing.currency, "Paying in invalid currency.");
            require(tokenXs[_currency] != address(0), "Marketplace: invalid currency");
            targetTotalPrice = _quantity * listing.pricePerToken;
        }

        require(targetTotalPrice == _expectedTotalPrice, "Unexpected total price");

        // Check: buyer owns and has approved sufficient currency for sale.
        if (_currency == CurrencyTransferLib.NATIVE_TOKEN) {
            require(msg.value == targetTotalPrice, "Marketplace: msg.value must exactly be the total price.");
        } else {
            require(msg.value == 0, "Marketplace: invalid native tokens sent.");
            _validateERC20BalAndAllowance(buyer, _currency, targetTotalPrice);
        }

        // PERPETUAL:
        // - never set listing as completed or modify quantity

        // if (listing.quantity == _quantity) {
        //     _directListingsStorage().listings[_listingId].status = IDirectListings.Status.COMPLETED;
        // }
        // _directListingsStorage().listings[_listingId].quantity -= _quantity;

        address currentListingOwner = _currentListingNFTOwner(listing);

        uint256 minimumTaxDue = _taxDuePerWeek(listing.taxRate, targetTotalPrice);

        require(
            ISuperToken(tokenXs[_currency]).balanceOf(_buyFor) >= minimumTaxDue,
            "Marketplace: TokenX insufficient balance"
        );

        _payout(buyer, currentListingOwner, _currency, targetTotalPrice, listing);

        _handleTaxStreams(_currency, currentListingOwner, buyer, listing.taxBeneficiary, listing);

        // PERPETUAL:
        // - transfer from direct owner of NFT instead of listing creator
        // _transferListingTokens(listing.listingCreator, _buyFor, _quantity, listing);
        _transferListingTokens(currentListingOwner, _buyFor, _quantity, listing);

        _directListingsStorage().listings[_listingId].listingOwner = _buyFor;

        emit NewSale(
            currentListingOwner,
            listing.listingId,
            listing.assetContract,
            listing.tokenId,
            buyer,
            _quantity,
            targetTotalPrice
        );
    }

    /// @notice Set the tokenX address for a currency
    function setTokenX(address underlyingToken, address superToken) external onlyTaxManagerRole {
        tokenXs[underlyingToken] = superToken;

        emit TokenXSet(underlyingToken, superToken);
    }

    /*///////////////////////////////////////////////////////////////
                            View functions
    //////////////////////////////////////////////////////////////*/

    /**
     *  @notice Returns the total number of listings created.
     *  @dev At any point, the return value is the ID of the next listing created.
     */
    function totalListings() external view returns (uint256) {
        return _directListingsStorage().totalListings;
    }

    /// @notice Returns whether a buyer is approved for a listing.
    function isBuyerApprovedForListing(uint256 _listingId, address _buyer) external view returns (bool) {
        return _directListingsStorage().isBuyerApprovedForListing[_listingId][_buyer];
    }

    /// @notice Returns whether a currency is approved for a listing.
    function isCurrencyApprovedForListing(uint256 _listingId, address _currency) external view returns (bool) {
        return _directListingsStorage().currencyPriceForListing[_listingId][_currency] > 0;
    }

    /// @notice Returns the price per token for a listing, in the given currency.
    function currencyPriceForListing(uint256 _listingId, address _currency) external view returns (uint256) {
        if (_directListingsStorage().currencyPriceForListing[_listingId][_currency] == 0) {
            revert("Currency not approved for listing");
        }

        return _directListingsStorage().currencyPriceForListing[_listingId][_currency];
    }

    /// @notice Returns all non-cancelled listings.
    function getAllListings(uint256 _startId, uint256 _endId) external view returns (Listing[] memory _allListings) {
        require(_startId <= _endId && _endId < _directListingsStorage().totalListings, "invalid range");

        _allListings = new Listing[](_endId - _startId + 1);

        for (uint256 i = _startId; i <= _endId; i += 1) {
            _allListings[i - _startId] = _directListingsStorage().listings[i];
        }
    }

    /**
     *  @notice Returns all valid listings between the start and end Id (both inclusive) provided.
     *          A valid listing is where the listing creator still owns and has approved Marketplace
     *          to transfer the listed NFTs.
     */
    function getAllValidListings(
        uint256 _startId,
        uint256 _endId
    ) external view returns (Listing[] memory _validListings) {
        require(_startId <= _endId && _endId < _directListingsStorage().totalListings, "invalid range");

        Listing[] memory _listings = new Listing[](_endId - _startId + 1);
        uint256 _listingCount;

        for (uint256 i = _startId; i <= _endId; i += 1) {
            _listings[i - _startId] = _directListingsStorage().listings[i];
            if (_validateExistingListing(_listings[i - _startId])) {
                _listingCount += 1;
            }
        }

        _validListings = new Listing[](_listingCount);
        uint256 index = 0;
        uint256 count = _listings.length;
        for (uint256 i = 0; i < count; i += 1) {
            if (_validateExistingListing(_listings[i])) {
                _validListings[index++] = _listings[i];
            }
        }
    }

    /// @notice Returns a listing at a particular listing ID.
    function getListing(uint256 _listingId) external view returns (Listing memory listing) {
        listing = _directListingsStorage().listings[_listingId];
    }

    /*///////////////////////////////////////////////////////////////
                            Internal functions
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns the next listing Id.
    function _getNextListingId() internal returns (uint256 id) {
        id = _directListingsStorage().totalListings;
        _directListingsStorage().totalListings += 1;
    }

    /// @dev Returns the interface supported by a contract.
    function _getTokenType(address _assetContract) internal view returns (TokenType tokenType) {
        if (IERC165(_assetContract).supportsInterface(type(IERC1155).interfaceId)) {
            tokenType = TokenType.ERC1155;
        } else if (IERC165(_assetContract).supportsInterface(type(IERC721).interfaceId)) {
            tokenType = TokenType.ERC721;
        } else {
            revert("Marketplace: listed token must be ERC1155 or ERC721.");
        }
    }

    /// @dev Checks whether the listing creator owns and has approved marketplace to transfer listed tokens.
    function _validateNewListing(ListingParameters memory _params, TokenType _tokenType) internal view {
        require(_params.quantity > 0, "Marketplace: listing zero quantity.");
        require(_params.quantity == 1 || _tokenType == TokenType.ERC1155, "Marketplace: listing invalid quantity.");

        require(
            _validateOwnershipAndApproval(
                _msgSender(),
                _params.assetContract,
                _params.tokenId,
                _params.quantity,
                _tokenType
            ),
            "Marketplace: not owner or approved tokens."
        );
    }

    /// @dev Checks whether the listing exists, is active, and if the lister has sufficient balance.
    function _validateExistingListing(Listing memory _targetListing) internal view returns (bool isValid) {
        isValid =
            _targetListing.startTimestamp <= block.timestamp &&
            _targetListing.endTimestamp > block.timestamp &&
            _targetListing.status == IDirectListings.Status.CREATED &&
            _validateOwnershipAndApproval(
                _currentListingNFTOwner(_targetListing),
                _targetListing.assetContract,
                _targetListing.tokenId,
                _targetListing.quantity,
                _targetListing.tokenType
            );
    }

    /// @dev Validates that `_tokenOwner` owns and has approved Marketplace to transfer NFTs.
    function _validateOwnershipAndApproval(
        address _tokenOwner,
        address _assetContract,
        uint256 _tokenId,
        uint256 _quantity,
        TokenType _tokenType
    ) internal view returns (bool isValid) {
        // return true;
        address market = address(this);

        if (_tokenType == TokenType.ERC1155) {
            isValid =
                IERC1155(_assetContract).balanceOf(_tokenOwner, _tokenId) >= _quantity &&
                IERC1155(_assetContract).isApprovedForAll(_tokenOwner, market);
        } else if (_tokenType == TokenType.ERC721) {
            address owner;
            address operator;

            // failsafe for reverts in case of non-existent tokens
            try IERC721(_assetContract).ownerOf(_tokenId) returns (address _owner) {
                owner = _owner;

                // Nesting the approval check inside this try block, to run only if owner check doesn't revert.
                // If the previous check for owner fails, then the return value will always evaluate to false.
                try IERC721(_assetContract).getApproved(_tokenId) returns (address _operator) {
                    operator = _operator;
                } catch {}
            } catch {}

            isValid =
                owner == _tokenOwner &&
                (operator == market || IERC721(_assetContract).isApprovedForAll(_tokenOwner, market));
        }
    }

    /// @dev Validates that `_tokenOwner` owns and has approved Markeplace to transfer the appropriate amount
    /// of currency
    function _validateERC20BalAndAllowance(address _tokenOwner, address _currency, uint256 _amount) internal view {
        require(
            IERC20(_currency).balanceOf(_tokenOwner) >= _amount &&
                IERC20(_currency).allowance(_tokenOwner, address(this)) >= _amount,
            "!BAL20"
        );
    }

    /// @dev Transfers tokens listed for sale in a direct or auction listing.
    function _transferListingTokens(address _from, address _to, uint256 _quantity, Listing memory _listing) internal {
        if (_listing.tokenType == TokenType.ERC1155) {
            IERC1155(_listing.assetContract).safeTransferFrom(_from, _to, _listing.tokenId, _quantity, "");
        } else if (_listing.tokenType == TokenType.ERC721) {
            IERC721(_listing.assetContract).safeTransferFrom(_from, _to, _listing.tokenId, "");
        }
    }

    /// @dev Pays out stakeholders in a sale.
    function _payout(
        address _payer,
        address _payee,
        address _currencyToUse,
        uint256 _totalPayoutAmount,
        Listing memory _listing
    ) internal {
        address _nativeTokenWrapper = nativeTokenWrapper;
        uint256 amountRemaining;

        // Payout platform fee
        {
            (address platformFeeRecipient, uint16 platformFeeBps) = IPlatformFee(address(this)).getPlatformFeeInfo();
            uint256 platformFeeCut = (_totalPayoutAmount * platformFeeBps) / MAX_BPS;

            // Transfer platform fee
            CurrencyTransferLib.transferCurrencyWithWrapper(
                _currencyToUse,
                _payer,
                platformFeeRecipient,
                platformFeeCut,
                _nativeTokenWrapper
            );

            amountRemaining = _totalPayoutAmount - platformFeeCut;
        }

        // Payout royalties
        {
            // Get royalty recipients and amounts
            (address payable[] memory recipients, uint256[] memory amounts) = RoyaltyPaymentsLogic(address(this))
                .getRoyalty(_listing.assetContract, _listing.tokenId, _totalPayoutAmount);

            uint256 royaltyRecipientCount = recipients.length;

            if (royaltyRecipientCount != 0) {
                uint256 royaltyCut;
                address royaltyRecipient;

                for (uint256 i = 0; i < royaltyRecipientCount; ) {
                    royaltyRecipient = recipients[i];
                    royaltyCut = amounts[i];

                    // Check payout amount remaining is enough to cover royalty payment
                    require(amountRemaining >= royaltyCut, "fees exceed the price");

                    // Transfer royalty
                    CurrencyTransferLib.transferCurrencyWithWrapper(
                        _currencyToUse,
                        _payer,
                        royaltyRecipient,
                        royaltyCut,
                        _nativeTokenWrapper
                    );

                    unchecked {
                        amountRemaining -= royaltyCut;
                        ++i;
                    }
                }
            }
        }

        // Distribute price to token owner
        CurrencyTransferLib.transferCurrencyWithWrapper(
            _currencyToUse,
            _payer,
            _payee,
            amountRemaining,
            _nativeTokenWrapper
        );
    }

    function _handleTaxStreams(
        address _currency,
        address previousSender,
        address newSender,
        address receiver,
        Listing memory listing
    ) internal {
        int96 listingFlowRate = _getFlowRate(listing.taxRate, listing.pricePerToken);

        (, int96 previousSenderFlowRate, , ) = ISuperToken(tokenXs[_currency]).getFlowInfo(previousSender, receiver);

        // Cancel of reduce stream flow of account about to sell the NFT
        if (receiver != _currentListingNFTOwner(listing)) {
            if (previousSenderFlowRate > listingFlowRate)
                _updateStream(_currency, previousSender, receiver, previousSenderFlowRate - listingFlowRate);
            else _cancelStream(_currency, previousSender, receiver);
        }

        (, int96 newSenderFlowRate, , ) = ISuperToken(tokenXs[_currency]).getFlowInfo(newSender, receiver);

        // Create or update stream flow of account about to buy the NFT
        if (newSenderFlowRate == 0) {
            _createStream(_currency, newSender, receiver, listingFlowRate);
        } else {
            _updateStream(_currency, newSender, receiver, listingFlowRate + newSenderFlowRate);
        }
    }

    function _createStream(address currency, address sender, address receiver, int96 flowRate) internal {
        ISuperToken(tokenXs[currency]).createFlowFrom(sender, receiver, flowRate);
    }

    function _updateStream(address currency, address sender, address receiver, int96 flowRate) internal {
        ISuperToken(tokenXs[currency]).updateFlowFrom(sender, receiver, flowRate);
    }

    function _cancelStream(address currency, address sender, address receiver) internal {
        ISuperToken(tokenXs[currency]).deleteFlowFrom(sender, receiver);
    }

    function _getFlowRate(uint256 taxRateBPS, uint256 price) internal pure returns (int96) {
        uint256 duePerWeek = _taxDuePerWeek(taxRateBPS, price);

        return int96(int256(duePerWeek / 7 days));
    }

    function _taxDuePerWeek(uint256 taxRateBPS, uint256 price) internal pure returns (uint256) {
        return (price * taxRateBPS) / MAX_BPS;
    }

    function _currentListingNFTOwner(Listing memory _listing) internal view returns (address) {
        // PERPETUAL: Replace the listingCreator concept with the current owner of the NFT silently
        return _ownerOfERC721(_listing.assetContract, _listing.tokenId);
    }

    function _ownerOfERC721(address _assetContract, uint256 _tokenId) internal view returns (address) {
        return IERC721(_assetContract).ownerOf(_tokenId);
    }

    /// @dev Returns the DirectListings storage.
    function _directListingsStorage() internal pure returns (DirectListingsStorage.Data storage data) {
        data = DirectListingsStorage.data();
    }
}
