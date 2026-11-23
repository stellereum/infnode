//! infmail-chunkcheck — проверка чанков по манифестам m:/f: в kv.json.
//!
//! Сборка: zig build-exe infmail-chunkcheck.zig -femit-bin=../../bin/infmail-chunkcheck

const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();
    _ = args_iter.skip();
    const data_dir_path = args_iter.next() orelse "/opt/infnode";

    const dir = std.Io.Dir.openDir(.cwd(), io, data_dir_path, .{}) catch |err| {
        std.debug.print("error: cannot open '{s}': {t}\n", .{ data_dir_path, err });
        std.process.exit(2);
    };
    defer dir.close(io);

    // читаем kv.json
    const kv_file = dir.openFile(io, "kv.json", .{}) catch |err| {
        std.debug.print("error: kv.json: {t}\n", .{err});
        std.process.exit(2);
    };
    defer kv_file.close(io);
    const kv_stat = kv_file.stat(io) catch {
        std.debug.print("error: stat kv.json\n", .{});
        std.process.exit(2);
    };
    const kv_buf = allocator.alloc(u8, kv_stat.size) catch {
        std.debug.print("error: alloc kv_buf\n", .{});
        std.process.exit(2);
    };
    defer allocator.free(kv_buf);
    _ = kv_file.readPositionalAll(io, kv_buf, 0) catch {
        std.debug.print("error: readPositionalAll\n", .{});
        std.process.exit(2);
    };

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, kv_buf, .{}) catch {
        std.debug.print("error: parse kv.json\n", .{});
        std.process.exit(2);
    };
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) {
        std.debug.print("error: kv.json not object\n", .{});
        std.process.exit(1);
    }

    var total_mf: u64 = 0;
    var total_chunks: u64 = 0;
    var missing: u64 = 0;
    var mismatch: u64 = 0;

    var it = root.object.iterator();
    while (it.next()) |entry| {
        if (!std.mem.startsWith(u8, entry.key_ptr.*, "m:") and !std.mem.startsWith(u8, entry.key_ptr.*, "f:")) continue;
        const v = entry.value_ptr.*;
        if (v != .object) continue;
        const value_field = v.object.get("value") orelse continue;
        if (value_field != .string) continue;

        total_mf += 1;
        const manifest_parsed = std.json.parseFromSlice(std.json.Value, allocator, value_field.string, .{}) catch continue;
        defer manifest_parsed.deinit();
        const manifest = manifest_parsed.value;
        if (manifest != .object) continue;
        const bucket = if (manifest.object.get("bucket")) |b| if (b == .string) b.string else "files" else "files";
        const chunks = manifest.object.get("chunks") orelse continue;
        if (chunks != .array) continue;

        for (chunks.array.items) |c| {
            if (c != .object) continue;
            const cid = c.object.get("id") orelse continue;
            if (cid != .string) continue;
            total_chunks += 1;

            var chunk_path_buf: [512]u8 = undefined;
            const chunk_path = std.fmt.bufPrint(&chunk_path_buf, "chunks/{s}/{s}", .{ bucket, cid.string }) catch continue;

            const file = dir.openFile(io, chunk_path, .{}) catch {
                missing += 1;
                std.debug.print("MISSING: {s} bucket={s}\n", .{ cid.string, bucket });
                continue;
            };
            defer file.close(io);

            const expected = c.object.get("hash");
            if (expected) |h| {
                if (h == .string) {
                    const s = file.stat(io) catch continue;
                    const data = allocator.alloc(u8, s.size) catch continue;
                    defer allocator.free(data);
                    _ = file.readPositionalAll(io, data, 0) catch continue;
                    var actual: [32]u8 = undefined;
                    std.crypto.hash.Blake3.hash(data, &actual, .{});
                    var actual_hex: [64]u8 = undefined;
                    const ah = std.fmt.bufPrint(&actual_hex, "{x}", .{actual}) catch continue;
                    if (!std.mem.eql(u8, ah, h.string)) {
                        mismatch += 1;
                        std.debug.print("MISMATCH: {s} expected={s} actual={s}\n", .{ cid.string, h.string, ah });
                    }
                }
            }
        }
    }

    std.debug.print("---\nmanifests: {}\nchunks: {}\nmissing: {}\nmismatch: {}\n", .{ total_mf, total_chunks, missing, mismatch });
}