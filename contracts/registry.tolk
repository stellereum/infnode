
tolk 1.4.1

import "@stdlib/common"

struct Storage {
    registry: map<uint256, address>   // emailHash → wallet address (actual sender, not from body)
    adminAddress: address
    // Pricing tiers (in nanoTON)
    price_2_letters: coins            // 1 TON
    price_3_letters: coins            // 1 TON
    price_4_letters: coins            // 0.7 TON
    price_5_letters: coins            // 0.5 TON
    price_default: coins              // 0.1 TON (6+ letters)
    // Reserved names (e.g. 1-letter, premium brands)
    reserved: map<uint256, bool>      // emailHash → true if reserved (owner-only)
    // NftCollection, которой разрешено удалять записи при mint (необратимость web3→NFT).
    // Хранится в ОТДЕЛЬНОЙ ячейке (не ломает 1023-битный лимит data). Пустая = не задана.
    // ЗАДАЁТСЯ ДИНАМИЧЕСКИ админом (SETC) после деплоя — не хардкод (иначе цепочка передеплоев).
    authorizedCaller: cell
}

fun Storage.load(): Storage {
    return Storage.fromCell(contract.getData());
}

fun Storage.save(self) {
    contract.setData(self.toCell());
}

// ─── Message Handler ───────────────────────────────────────

fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) { return; }

    val op = in.body.loadUint(32);

    if (op == 0x52475a4b) {
        val emailHash = in.body.loadUint(256);
        val usernameLength = in.body.loadUint(8);
        var storage = lazy Storage.load();

        // 1. Check if name is reserved (1-letter, premium, or owner-locked)
        if (storage.reserved.exists(emailHash)) {
            throw 1004;  // Name is reserved (only owner can register)
        }

        // 2. Check if already registered
        if (storage.registry.exists(emailHash)) {
            throw 1002;
        }

        // 3. Determine expected price based on username length
        val expectedPrice: coins =
            usernameLength == 2 ? storage.price_2_letters :
            usernameLength == 3 ? storage.price_3_letters :
            usernameLength == 4 ? storage.price_4_letters :
            usernameLength == 5 ? storage.price_5_letters :
            usernameLength <= 1 ? 0 :
            storage.price_default;

        // 4. 1-letter names: only admin can register, no payment required
        if (usernameLength <= 1) {
            if (in.senderAddress != storage.adminAddress) {
                throw 1005;  // Only owner can register 1-letter names
            }
        } else {
            if (in.valueCoins < expectedPrice) {
                throw 1003;  // Insufficient payment
            }
        }

        // 5. Save: bind email to the ACTUAL sender (in.senderAddress), NOT to a
        //    walletRef from the message body. This prevents front-running: an attacker
        //    cannot register someone else's email to their own wallet.
        storage.registry.set(emailHash, in.senderAddress);
        storage.save();
    } else if (op == 0x57445257) {
        var storage = lazy Storage.load();
        if (in.senderAddress != storage.adminAddress) {
            throw 401;
        }
        val amount = in.body.loadCoins();
        val reserve: coins = 10000000;
        val balance: coins = contract.getOriginalBalance();
        if (amount == 0) {
            val available = balance - reserve;
            if (available > 0) {
                sendWithdrawal(storage.adminAddress, available);
            }
        } else {
            if (balance - amount >= reserve) {
                sendWithdrawal(storage.adminAddress, amount);
            }
        }
    } else if (op == 0x55505243) {
        var storage = lazy Storage.load();
        if (in.senderAddress != storage.adminAddress) {
            throw 401;
        }
        storage.price_2_letters = in.body.loadCoins();
        storage.price_3_letters = in.body.loadCoins();
        storage.price_4_letters = in.body.loadCoins();
        storage.price_5_letters = in.body.loadCoins();
        storage.price_default = in.body.loadCoins();
        storage.save();
    } else if (op == 0x52455352) {
        var storage = lazy Storage.load();
        if (in.senderAddress != storage.adminAddress) {
            throw 401;
        }
        val emailHash = in.body.loadUint(256);
        val reserved = in.body.loadUint(1) == 1;
        if (reserved) {
            storage.reserved.set(emailHash, true);
        } else {
            storage.reserved.delete(emailHash);
        }
        storage.save();
    } else if (op == 0x524e5247) {
        // Unregister (UNRG): НЕОБРАТИМОЕ сжигание записи — web3 почта становится NFT.
        // Разрешено: владелец записи, admin, или AUTHORIZED_COLLECTION (при mint).
        var storage = lazy Storage.load();
        val emailHash = in.body.loadUint(256);
        if (!storage.registry.exists(emailHash)) {
            throw 1006;  // нет такой записи
        }
        val isAdmin = in.senderAddress == storage.adminAddress;
        // сравнение по hash+workchain (не по флагу bounceable) — иначе коллекция шлёт
        // с bounceable адреса (EQ...), а authorizedCaller non-bounceable (kQ...) → false.
        var isColl = false;
        if (storage.authorizedCaller.beginParse().remainingBitsCount() != 0) {
            val caller = storage.authorizedCaller.beginParse().loadAddress();
            val (wc1, h1) = in.senderAddress.getWorkchainAndHash();
            val (wc2, h2) = caller.getWorkchainAndHash();
            isColl = wc1 == wc2 && h1 == h2;
        }
        if (!isAdmin && !isColl) {
            val owner = storage.registry.get(emailHash);
            if (owner.isFound && owner.loadValue() != in.senderAddress) {
                throw 401;  // не владелец, не admin, не коллекция
            }
        }
        // ЖЁСТКАЯ НЕОБРАТИМОСТЬ: запись удаляется, а имя помечается reserved —
        // повторная регистрация этого email БЛОКИРУЕТСЯ навсегда (register → throw 1004).
        storage.registry.delete(emailHash);
        storage.reserved.set(emailHash, true);
        storage.save();
    } else if (op == 0x53455443) {
        // SetCaller (SETC): admin задаёт адрес коллекции (динамическая связь, без передеплоев).
        var storage = lazy Storage.load();
        if (in.senderAddress != storage.adminAddress) {
            throw 401;
        }
        val caller = in.body.loadAddress();
        storage.authorizedCaller = beginCell().storeAddress(caller).endCell();
        storage.save();
    } else {
        throw 0xFFFF;
    }
}

fun sendWithdrawal(to: address, amount: coins) {
    var msg = beginCell()
        .storeUint(0x10, 6) // nobounce
        .storeAddress(to)
        .storeCoins(amount)
        .storeUint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
        .endCell();
    sendRawMessage(msg, 1);
}

// Get methods
get fun getOwnerByHash(hash: int): address? {
    val storage = lazy Storage.load();
    val result = storage.registry.get(hash as uint256);
    if (result.isFound) {
        return result.loadValue();
    }
    return null;
}

get fun getAdminAddress(): address {
    val storage = lazy Storage.load();
    return storage.adminAddress;
}

get fun getPricing(): (int, int, int, int, int) {
    val storage = lazy Storage.load();
    return (
        storage.price_2_letters as int,
        storage.price_3_letters as int,
        storage.price_4_letters as int,
        storage.price_5_letters as int,
        storage.price_default as int,
    );
}

get fun isReserved(hash: int): bool {
    val storage = lazy Storage.load();
    return storage.reserved.exists(hash as uint256);
}
