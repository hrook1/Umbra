// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EncryptedContacts
/// @notice Privacy-preserving contact list using tagged encryption
/// @dev Contacts are stored encrypted, only the owner can decrypt them
contract EncryptedContacts {

    struct EncryptedContact {
        bytes8 ownerTag;              // First 8 bytes of keccak256(ownerPubKey) - for lookup
        bytes encryptedData;          // Encrypted: name + address + metadata
        uint256 timestamp;
    }

    // All contacts stored on-chain
    EncryptedContact[] public allContacts;

    // Mapping from owner tag to their contact indices
    mapping(bytes8 => uint256[]) public contactsByOwner;

    // Events
    event ContactSaved(
        uint256 indexed contactId,
        bytes8 indexed ownerTag,
        bytes encryptedData,
        uint256 timestamp
    );

    event ContactUpdated(
        uint256 indexed contactId,
        bytes8 indexed ownerTag,
        bytes encryptedData,
        uint256 timestamp
    );

    event ContactDeleted(
        uint256 indexed contactId,
        bytes8 indexed ownerTag
    );

    // Errors
    error InvalidContact();
    error ContactNotFound();
    error EmptyData();

    /// @notice Save a new encrypted contact
    /// @param _ownerTag First 8 bytes of keccak256(ownerPubKey)
    /// @param _encryptedData Encrypted contact data (name, address, etc)
    /// @return contactId The ID of the saved contact
    function saveContact(
        bytes8 _ownerTag,
        bytes calldata _encryptedData
    ) external returns (uint256) {
        if (_ownerTag == bytes8(0)) revert InvalidContact();
        if (_encryptedData.length == 0) revert EmptyData();

        uint256 contactId = allContacts.length;

        allContacts.push(EncryptedContact({
            ownerTag: _ownerTag,
            encryptedData: _encryptedData,
            timestamp: block.timestamp
        }));

        contactsByOwner[_ownerTag].push(contactId);

        emit ContactSaved(
            contactId,
            _ownerTag,
            _encryptedData,
            block.timestamp
        );

        return contactId;
    }

    /// @notice Update an existing contact's encrypted data
    /// @param _contactId The contact ID to update
    /// @param _encryptedData New encrypted contact data
    function updateContact(
        uint256 _contactId,
        bytes calldata _encryptedData
    ) external {
        if (_contactId >= allContacts.length) revert ContactNotFound();
        if (_encryptedData.length == 0) revert EmptyData();

        EncryptedContact storage contact = allContacts[_contactId];
        contact.encryptedData = _encryptedData;
        contact.timestamp = block.timestamp;

        emit ContactUpdated(
            _contactId,
            contact.ownerTag,
            _encryptedData,
            block.timestamp
        );
    }

    /// @notice Mark a contact as deleted (sets data to empty)
    /// @param _contactId The contact ID to delete
    function deleteContact(uint256 _contactId) external {
        if (_contactId >= allContacts.length) revert ContactNotFound();

        EncryptedContact storage contact = allContacts[_contactId];
        bytes8 ownerTag = contact.ownerTag;

        // Clear the data but keep the entry (maintains index consistency)
        delete contact.encryptedData;
        contact.timestamp = block.timestamp;

        emit ContactDeleted(_contactId, ownerTag);
    }

    /// @notice Get all contact IDs for an owner tag
    /// @param _ownerTag The owner tag to lookup
    /// @return Array of contact IDs
    function getContactsByOwner(bytes8 _ownerTag) external view returns (uint256[] memory) {
        return contactsByOwner[_ownerTag];
    }

    /// @notice Get contact details by ID
    /// @param _contactId The contact ID
    /// @return The full contact struct
    function getContact(uint256 _contactId) external view returns (EncryptedContact memory) {
        if (_contactId >= allContacts.length) revert ContactNotFound();
        return allContacts[_contactId];
    }

    /// @notice Get multiple contacts by IDs
    /// @param _contactIds Array of contact IDs
    /// @return Array of contact structs
    function getContacts(uint256[] calldata _contactIds) external view returns (EncryptedContact[] memory) {
        EncryptedContact[] memory contacts = new EncryptedContact[](_contactIds.length);
        for (uint i = 0; i < _contactIds.length; i++) {
            if (_contactIds[i] < allContacts.length) {
                contacts[i] = allContacts[_contactIds[i]];
            }
        }
        return contacts;
    }

    /// @notice Get total number of contacts
    /// @return Total count
    function getContactCount() external view returns (uint256) {
        return allContacts.length;
    }
}
