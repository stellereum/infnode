
tolk 1.4.1

import "@stdlib/common"

struct Storage {
    adminAddress: address
    totalPayments: coins
    // Награды нод: count(8) + (address, weight:uint64)*
    // weight = доля работы (напр. хранимые байты почты/файлов)
    nodes: cell
}

fun Storage.load(): Storage {
    return Storage.fromCell(contract.getData());
}

fun Storage.save(self) {
    contract.setData(self.toCell());
}

// Opcode 0x54555053: Topup Storage
struct (0x54555053) TopupStorage {}

// Opcode 0x57445257: Withdraw (WDRW) — admin only
struct (0x57445257) Withdraw {
    amount: coins
}

// Opcode 0x5345544e: SetNodes (STN) — admin only, конфиг наград нод
struct (0x5345544e) SetNodes {
    nodes: cell
}

// Opcode 0x44495354: Distribute (DSTR) — admin only, 30% admin / 70% ноды по весам
struct (0x44495354) Distribute {}

type AllowedMessage = TopupStorage | Withdraw | SetNodes | Distribute

const MIN_RESERVE = ton("0.01")
const ADMIN_SHARE = 30
const NODE_SHARE = 70

fun makeSend(to: address, amount: coins): cell {
    return beginCell()
        .storeUint(0x18, 6)
        .storeAddress(to)
        .storeCoins(amount)
        .storeUint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
        .endCell();
}

fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) { return; }

    // Текстовый комментарий (опкод 0) = платёж подписки INFMAIL_SUB:<email>:<nonce>
    if (in.body.preloadUint(32) == 0) {
        var storage = lazy Storage.load();
        storage.totalPayments += in.valueCoins;
        storage.save();
        return;
    }

    var storage = lazy Storage.load();
    val msg = lazy AllowedMessage.fromSlice(in.body);

    match (msg) {
        TopupStorage => {
            storage.totalPayments += in.valueCoins;
            storage.save();
        }

        Withdraw => {
            if (in.senderAddress != storage.adminAddress) {
                throw 401;
            }
            // Резерв на комиссию исходящего сообщения: иначе при amount=0 (вывести всё)
            // контракту не хватит TON на fees → Action failed ("Not enough Toncoin").
            val balance = contract.getOriginalBalance();
            val withdrawAmount: coins = msg.amount == 0
                ? (balance > MIN_RESERVE ? balance - MIN_RESERVE : 0)
                : (msg.amount <= balance - MIN_RESERVE ? msg.amount : (balance > MIN_RESERVE ? balance - MIN_RESERVE : 0));
            if (withdrawAmount > 0) {
                sendRawMessage(makeSend(storage.adminAddress, withdrawAmount), 1);
            }
        }

        SetNodes => {
            if (in.senderAddress != storage.adminAddress) {
                throw 401;
            }
            storage.nodes = msg.nodes;
            storage.save();
        }

        Distribute => {
            if (in.senderAddress != storage.adminAddress) {
                throw 401;
            }
            distribute(storage);
        }

        else => {
            throw 0xFFFF;
        }
    }
}

/// Распределение: 30% — валидатору (admin), 70% — нодам пропорционально весам работы.
fun distribute(storage: Storage) {
    val balance = contract.getOriginalBalance();
    if (balance <= MIN_RESERVE) { return; }
    val available = balance - MIN_RESERVE;

    val toAdmin = available * ADMIN_SHARE / 100;
    val toNodes = available - toAdmin;

    if (toAdmin > 0) {
        sendRawMessage(makeSend(storage.adminAddress, toAdmin), 0);
    }
    if (toNodes <= 0) { return; }

    var nodesSlice = storage.nodes.beginParse();
    val count = nodesSlice.loadUint(8);
    if (count == 0) {
        sendRawMessage(makeSend(storage.adminAddress, toNodes), 0);
        return;
    }

    // суммарный вес всех нод
    var totalWeight: uint64 = 0;
    var i = 0;
    while (i < count) {
        _ = nodesSlice.loadAddress();
        totalWeight += nodesSlice.loadUint(64);
        i += 1;
    }
    if (totalWeight == 0) {
        sendRawMessage(makeSend(storage.adminAddress, toNodes), 0);
        return;
    }

    // рассылка долей
    var j = 0;
    var paidTotal: coins = 0;
    var nodesSlice2 = storage.nodes.beginParse();
    _ = nodesSlice2.loadUint(8);
    while (j < count) {
        val addr = nodesSlice2.loadAddress();
        val weight = nodesSlice2.loadUint(64);
        val share = toNodes * weight / totalWeight;
        if (share > 0) {
            sendRawMessage(makeSend(addr, share), 0);
            paidTotal += share;
        }
        j += 1;
    }
    // добивка остатка от целочисленного деления — админу (не копим в контракте)
    val remainder = toNodes - paidTotal;
    if (remainder > 0) {
        sendRawMessage(makeSend(storage.adminAddress, remainder), 0);
    }
}

get fun getTotalPayments(): coins {
    val storage = lazy Storage.load();
    return storage.totalPayments;
}

get fun getAdminAddress(): address {
    val storage = lazy Storage.load();
    return storage.adminAddress;
}

get fun getNodes(): cell {
    val storage = lazy Storage.load();
    return storage.nodes;
}
