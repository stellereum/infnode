
import "@stdlib/strings"
import "types"
import "errors"
import "messages"

const UPGRADE_PRICE = ton("1")
const MIN_BALANCE = ton("0.05")

contract NftCollection {
    author: "immtes"
    version: "1.1.0"
    description: "InfMail NFT Collection — optional upgrade from Web3 email to TEP-62 NFT"
    storage: Storage
    incomingMessages: AllowedMessageToCollection
}

type AllowedMessageToCollection =
    | Upgrade
    | Mint
    | Withdraw
    | RequestRoyaltyParams

fun deployNftItem(
    itemIndex: int,
    nftItemCode: cell,
    attachTonAmount: coins,
    initParams: Cell<NftItemInitAtDeployment>,
) {
    val deployMsg = createMessage({
        bounce: BounceMode.Only256BitsOfBody,
        dest: calcDeployedNftItem(itemIndex, contract.getAddress(), nftItemCode),
        value: attachTonAmount,
        body: initParams,
    });
    deployMsg.send(SEND_MODE_PAY_FEES_SEPARATELY);
}

fun onInternalMessage(in: InMessage) {
    val msg = lazy AllowedMessageToCollection.fromSlice(in.body);

    match (msg) {
        Upgrade => {
            var storage = lazy Storage.load();

            var m1 = storage.maps1.load();
            if (m1.emailToToken.exists(msg.emailHash)) { throw Errors.AlreadyUpgrading; }
            if (m1.pendingWallet.exists(msg.walletHash)) { throw Errors.AlreadyUpgrading; }

            var m2 = storage.maps2.load();
            if (m2.pendingEmail.exists(msg.emailHash)) { throw Errors.AlreadyUpgrading; }

            if (in.valueCoins < UPGRADE_PRICE) { throw Errors.NotEnoughTon; }

            val tokenId = storage.nextItemIndex;
            m1.pendingWallet.set(msg.walletHash, tokenId);
            m2.pendingEmail.set(msg.emailHash, msg.walletHash);

            storage.maps1 = m1.toCell();
            storage.maps2 = m2.toCell();
            storage.nextItemIndex = tokenId + 1;
            storage.save();
        }

        Mint => {
            var storage = lazy Storage.load();
            if (in.senderAddress != storage.adminAddress) { throw Errors.NotFromAdmin; }

            var m1 = storage.maps1.load();
            if (m1.tokenToOwner.exists(msg.tokenId)) { throw Errors.TokenAlreadyExists; }
            if (m1.emailToToken.exists(msg.emailHash)) { throw Errors.AlreadyUpgrading; }
            if (msg.tokenId >= storage.nextItemIndex) { throw Errors.NotFromAdmin; }

            var m2 = storage.maps2.load();
            if (!m2.pendingEmail.exists(msg.emailHash)) { throw Errors.UpgradeNotPending; }

            val extra = storage.extra.load();

            deployNftItem(msg.tokenId as int, extra.nftItemCode, ton("0.02"), NftItemInitAtDeployment {
                ownerAddress: msg.ownerAddress,
                // off-chain content (TEP-64): 0x01 + URI → GetGems подтянет метаданные.
                // База: коллекция резолвит meta по индексу (бэкенд: /api/v1/nft/{token_id}/meta).
                content: beginCell()
                    .storeUint(0x01, 8)
                    .storeString("https://infmail.org/api/v1/nft/meta/")
                    .endCell(),
            }.toCell());

            m1.emailToToken.set(msg.emailHash, msg.tokenId);
            m1.tokenToOwner.set(msg.tokenId, msg.ownerAddress);
            m2.tokenToEmail.set(msg.tokenId, msg.emailHash);
            m2.pendingEmail.delete(msg.emailHash);

            storage.maps1 = m1.toCell();
            storage.maps2 = m2.toCell();
            storage.save();

            // НЕОБРАТИМОСТЬ: web3-почта становится NFT — удаляем запись в Registry.
            // Registry-адрес задан в extra-конфиге коллекции при деплое (динамическая связь).
            if (extra.registryAddress != null) {
                val unregBody = beginCell()
                    .storeUint(0x524e5247, 32)  // UNRG
                    .storeUint(msg.emailHash, 256)
                    .endCell();
                val unregMsg = createMessage({
                    bounce: false,
                    dest: extra.registryAddress!!,
                    value: ton("0.05"),
                    body: unregBody,
                });
                unregMsg.send(SEND_MODE_PAY_FEES_SEPARATELY);
            }
        }

        Withdraw => {
            var storage = lazy Storage.load();
            if (in.senderAddress != storage.adminAddress) { throw Errors.NotFromAdmin; }

            val balance = contract.getOriginalBalance();
            val sendAmount = balance - MIN_BALANCE;
            if (sendAmount <= 0) { return; }

            val respondMsg = createMessage({
                bounce: BounceMode.NoBounce,
                dest: in.senderAddress,
                value: sendAmount,
                body: beginCell().storeUint(0, 32).endCell(),
            });
            respondMsg.send(SEND_MODE_PAY_FEES_SEPARATELY);
        }

        RequestRoyaltyParams => {
            val storage = lazy Storage.load();
            val extra = storage.extra.load();
            val respondMsg = createMessage({
                bounce: BounceMode.NoBounce,
                dest: in.senderAddress,
                value: 0,
                body: ResponseRoyaltyParams {
                    queryId: msg.queryId,
                    royaltyParams: extra.royaltyParams.load(),
                },
            });
            respondMsg.send(SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE);
        }

        else => {
            assert (in.body.isEmpty()) throw 0xFFFF;
        }
    }
}

fun onBouncedMessage(in: InMessageBounced) {
    in.bouncedBody.skipBouncedPrefix();
}

get fun getCollectionData(): (int, cell, address) {
    val storage = lazy Storage.load();
    return (storage.nextItemIndex as int, storage.collectionContent, storage.adminAddress);
}

get fun getNftAddressByIndex(itemIndex: int): address {
    val storage = lazy Storage.load();
    val extra = storage.extra.load();
    val nftDeployed = calcDeployedNftItem(itemIndex, contract.getAddress(), extra.nftItemCode);
    return nftDeployed.calculateAddress();
}

get fun royalty_params(): cell {
    val storage = lazy Storage.load();
    val extra = storage.extra.load();
    return extra.royaltyParams.toCell();
}

get fun getNftContent(
    _itemIndex: int,
    individualNftContent: string,
): Cell<OffchainMetadataReply> {
    return OffchainMetadataReply { string: individualNftContent }.toCell();
}

get fun getTokenByEmailHash(hash: uint256): int? {
    val storage = lazy Storage.load();
    val m1 = storage.maps1.load();
    val r = m1.emailToToken.get(hash);
    if (r.isFound) { return r.loadValue() as int; }
    return null;
}

get fun getOwnerByTokenId(tokenId: uint64): address? {
    val storage = lazy Storage.load();
    val m1 = storage.maps1.load();
    val r = m1.tokenToOwner.get(tokenId);
    if (r.isFound) { return r.loadValue(); }
    return null;
}

get fun getPendingToken(walletHash: uint256): int? {
    val storage = lazy Storage.load();
    val m1 = storage.maps1.load();
    val r = m1.pendingWallet.get(walletHash);
    if (r.isFound) { return r.loadValue() as int; }
    return null;
}
