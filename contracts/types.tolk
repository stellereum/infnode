
struct RoyaltyParams {
    numerator: uint16
    denominator: uint16
    royaltyAddress: address
}

struct ExtraConfig {
    nftItemCode: cell
    royaltyParams: Cell<RoyaltyParams>
    // Registry-контракт: при mint коллекция вызывает UNRG (необратимость web3→NFT).
    // Задаётся при деплое коллекции (динамическая связь, без хардкода в коде).
    registryAddress: address?
}

struct Maps1 {
    emailToToken: map<uint256, uint64>
    tokenToOwner: map<uint64, address>
    pendingWallet: map<uint256, uint64>
}

struct Maps2 {
    tokenToEmail: map<uint64, uint256>
    pendingEmail: map<uint256, uint256>
}

struct Storage {
    adminAddress: address
    nextItemIndex: uint64
    collectionContent: cell
    extra: Cell<ExtraConfig>
    maps1: Cell<Maps1>
    maps2: Cell<Maps2>
}

fun Storage.load(): Storage {
    return Storage.fromCell(contract.getData());
}

fun Storage.save(self) {
    contract.setData(self.toCell());
}

struct CollectionDataReply {
    nextItemIndex: int
    collectionContent: cell
    adminAddress: address
}

struct (0x01) OffchainMetadataReply {
    string: string
}

struct NftItemStorage {
    itemIndex: uint64
    collectionAddress: address
    ownerAddress: address
    content: cell
}

struct NftItemStorageNotInitialized {
    itemIndex: uint64
    collectionAddress: address
}

struct NftDataReply {
    isInitialized: bool
    itemIndex: int
    collectionAddress: address
    ownerAddress: address? = null
    content: cell? = null
}

fun NftItemStorage.startLoading(): NftItemStorageLoader {
    return NftItemStorageLoader.fromCell(contract.getData());
}

fun NftItemStorage.save(self) {
    contract.setData(self.toCell());
}

struct NftItemStorageLoader {
    itemIndex: uint64
    collectionAddress: address
    private rest: RemainingBitsAndRefs
}

fun NftItemStorageLoader.isNotInitialized(self): bool {
    return self.rest.isEmpty();
}

fun NftItemStorageLoader.endLoading(mutate self): NftItemStorage {
    return {
        itemIndex: self.itemIndex,
        collectionAddress: self.collectionAddress,
        ownerAddress: self.rest.loadAny(),
        content: self.rest.loadAny(),
    };
}

fun calcDeployedNftItem(
    itemIndex: uint64,
    collectionAddress: address,
    nftItemCode: cell,
): AutoDeployAddress {
    val emptyNftItemStorage: NftItemStorageNotInitialized = { itemIndex, collectionAddress };
    return { stateInit: { code: nftItemCode, data: emptyNftItemStorage.toCell() } };
}

