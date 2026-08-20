const std = @import("std");
const linux = std.os.linux;
const Io = std.Io;
const net = std.Io.net;

const AF_PACKET: u32 = 17;
const SOCK_RAW: u32 = 3;
const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
const SOL_PACKET: i32 = 263;
const PACKET_ADD_MEMBERSHIP: i32 = 1;
const PACKET_MR_PROMISC: u16 = 1;
const IPPROTO_UDP: u8 = 17;
const PACKET_OUTGOING: u8 = 4;

const REPLAY_FORMAT_VERSION = "0.0.2";
const ASSUMED_TICK_MS: f64 = 1000.0 / 30.0;
const TICKS_PER_SECOND: f64 = 30.0;
const DEFAULT_HTTP_PORT: u16 = 8765;
const MAX_WS_CLIENTS: usize = 32;
const ALLOWED_REPLAY_EXT = ".sv.replay.jsonl";
const MAX_STATIC_FILE: usize = 2 * 1024 * 1024;
const MAX_SESSION_FILE: usize = 64 * 1024 * 1024;
const MAX_FILTER_PORTS: usize = 64;
const PORT_REFRESH_NS: i128 = 1_000_000_000;
const STATUS_INTERVAL_NS: i128 = 5_000_000_000;
const DEFAULT_PROCESS_NAME = "SpiritVale"; // matches SpiritVale.exe too
const LITENET_PROP_MAX: u8 = 17;

const sockaddr_ll = extern struct {
    family: u16 = AF_PACKET,
    protocol: u16,
    ifindex: i32,
    hatype: u16 = 0,
    pkttype: u8 = 0,
    halen: u8 = 0,
    addr: [8]u8 = .{0} ** 8,
};

const packet_mreq = extern struct {
    mr_ifindex: i32,
    mr_type: u16,
    mr_alen: u16 = 0,
    mr_address: [8]u8 = .{0} ** 8,
};

const Config = struct {
    interface: ?[]const u8 = null,
    stdout: bool = false,
    log_dir: ?[]const u8 = null,
    log_file: ?[]const u8 = null,
    no_file: bool = false,
    http: bool = false,
    http_port: u16 = DEFAULT_HTTP_PORT,
    http_bind: []const u8 = "127.0.0.1",
    static_dir: []const u8 = "./static",
    sessions_dir: ?[]const u8 = null,
    open_browser: bool = false,
    help: bool = false,
    force_yes: bool = false,
    ports: [MAX_FILTER_PORTS]u16 = .{0} ** MAX_FILTER_PORTS,
    ports_len: usize = 0,
    auto_ports: bool = true,
    process_name: []const u8 = DEFAULT_PROCESS_NAME,
    litenet_filter: bool = true,
    all_udp: bool = false,
};

const UtcParts = struct { year: u16, month: u8, day: u8, hour: u8, min: u8, sec: u8 };

fn utcComponents() UtcParts {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.REALTIME, &ts);
    const secs: i64 = ts.sec;
    const days_total = @divFloor(secs, 86400);
    var rem = @mod(secs, 86400);
    if (rem < 0) rem += 86400;
    const hour: u8 = @intCast(@divFloor(rem, 3600));
    const min: u8 = @intCast(@divFloor(@mod(rem, 3600), 60));
    const sec: u8 = @intCast(@mod(rem, 60));

    const z = days_total + 719468;
    const era = @divFloor(z, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = @intCast(@divFloor(@as(i64, doe) - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365));
    const y: i32 = @intCast(@as(i64, yoe) + era * 400);
    const doy: u32 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: u32 = @divFloor(5 * doy + 2, 153);
    const d: u8 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    const year: u16 = @intCast(if (m <= 2) y + 1 else y);
    return .{ .year = year, .month = m, .day = d, .hour = hour, .min = min, .sec = sec };
}

fn monoNowNs() i128 {
    var ts: linux.timespec = undefined;
    switch (linux.errno(linux.clock_gettime(.MONOTONIC, &ts))) {
        .SUCCESS => {},
        else => return 0,
    }
    return @as(i128, ts.sec) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

fn directionFromPkttype(pkttype: u8) []const u8 {
    return if (pkttype == PACKET_OUTGOING) "out" else "in";
}

fn isPathSafe(name: []const u8) bool {
    if (name.len == 0) return false;
    if (std.mem.indexOf(u8, name, "..") != null) return false;
    if (std.mem.indexOfScalar(u8, name, '/') != null) return false;
    if (std.mem.indexOfScalar(u8, name, '\\') != null) return false;
    return true;
}

fn hasAllowedExt(name: []const u8) bool {
    return std.mem.endsWith(u8, name, ALLOWED_REPLAY_EXT);
}

fn mimeForPath(path: []const u8) []const u8 {
    if (std.mem.endsWith(u8, path, ".html") or std.mem.endsWith(u8, path, ".htm")) return "text/html; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".js")) return "application/javascript; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".css")) return "text/css; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".json") or std.mem.endsWith(u8, path, ".jsonl")) return "application/json; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".svg")) return "image/svg+xml";
    if (std.mem.endsWith(u8, path, ".png")) return "image/png";
    if (std.mem.endsWith(u8, path, ".ico")) return "image/x-icon";
    return "application/octet-stream";
}

fn asciiLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (hay.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        var ok = true;
        for (needle, 0..) |nc, j| {
            if (asciiLower(hay[i + j]) != asciiLower(nc)) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

fn looksLikeLiteNet(payload: []const u8) bool {
    if (payload.len == 0) return false;
    return (payload[0] & 0x1f) <= LITENET_PROP_MAX;
}

/// Read a small /proc file via openat-style absolute path (linux syscall — reliable under sudo).
fn readProcPath(path: []const u8, buf: []u8) ?[]const u8 {
    var path_z_buf: [128]u8 = undefined;
    if (path.len >= path_z_buf.len) return null;
    @memcpy(path_z_buf[0..path.len], path);
    path_z_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_z_buf);

    const fd_rc = linux.open(path_z, .{ .ACCMODE = .RDONLY }, 0);
    const fd: i32 = switch (linux.errno(fd_rc)) {
        .SUCCESS => @intCast(fd_rc),
        else => return null,
    };
    defer _ = linux.close(fd);

    const n_rc = linux.read(fd, buf.ptr, buf.len);
    const n: usize = switch (linux.errno(n_rc)) {
        .SUCCESS => @intCast(n_rc),
        else => return null,
    };
    return buf[0..n];
}

fn readlinkProcPath(path: []const u8, buf: []u8) ?[]const u8 {
    var path_z_buf: [128]u8 = undefined;
    if (path.len >= path_z_buf.len) return null;
    @memcpy(path_z_buf[0..path.len], path);
    path_z_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_z_buf);

    const n_rc = linux.readlink(path_z, buf.ptr, buf.len);
    const n: isize = @bitCast(n_rc);
    if (n < 0) return null;
    return buf[0..@intCast(n)];
}

const CaptureStats = struct {
    frames_total: u64 = 0,
    frames_non_ip: u64 = 0,
    frames_non_udp: u64 = 0,
    udp_seen: u64 = 0,
    rejected_no_ports: u64 = 0,
    rejected_port: u64 = 0,
    rejected_litenet: u64 = 0,
    accepted: u64 = 0,
    last_status_ns: i128 = 0,
    last_accepted_ns: i128 = 0,
    first_udp_logged: bool = false,
    first_accept_logged: bool = false,
    warned_no_ports: bool = false,
    warned_all_filtered: bool = false,
    process_hits: u64 = 0,

    fn maybeReport(self: *CaptureStats, cfg: *const Config) void {
        const now = monoNowNs();
        if (self.last_status_ns == 0) self.last_status_ns = now;
        if (now - self.last_status_ns < STATUS_INTERVAL_NS) return;
        self.last_status_ns = now;

        const ports = port_filter.portCount();
        const ws = hub.ws_count;

        std.log.info(
            "status: udp={d} accepted={d}  reject(no-ports={d} port={d} litenet={d})  filter-ports={d}  ws-clients={d}  process-matches={d}",
            .{
                self.udp_seen,
                self.accepted,
                self.rejected_no_ports,
                self.rejected_port,
                self.rejected_litenet,
                ports,
                ws,
                self.process_hits,
            },
        );

        if (ports == 0 and !cfg.all_udp) {
            if (!self.warned_no_ports) {
                self.warned_no_ports = true;
                std.log.warn(
                    \\No game UDP ports in the filter yet — nothing will be recorded or streamed.
                    \\  Watch discovery: lines above this for [discover] messages.
                    \\  Manual override:  --ports 34877,35655,...   (from: sudo ss -ulnp | grep -i spirit)
                    \\  Or:  --process-name SpiritVale.exe
                , .{});
            }
        } else if (self.udp_seen > 50 and self.accepted == 0 and !self.warned_all_filtered) {
            self.warned_all_filtered = true;
            if (self.rejected_litenet > self.rejected_port) {
                std.log.warn("LiteNetLib filter rejecting all — try --no-litenet-filter", .{});
            } else if (self.rejected_port > 0) {
                std.log.warn("UDP not on filtered ports — check ss / --ports", .{});
            }
        }

        if (cfg.http and ws == 0 and self.accepted > 0) {
            std.log.info("Packets recorded but no WS clients — open http://{s}:{d}/", .{ cfg.http_bind, cfg.http_port });
        }
        if (cfg.http and ws > 0 and self.accepted == 0) {
            std.log.info("WS client(s) connected, waiting for filtered game packets…", .{});
        }
    }
};

var stats: CaptureStats = .{};

const PortFilter = struct {
    mutex: Io.Mutex = .init,
    io: Io = undefined,
    manual: [MAX_FILTER_PORTS]u16 = .{0} ** MAX_FILTER_PORTS,
    manual_len: usize = 0,
    auto: [MAX_FILTER_PORTS]u16 = .{0} ** MAX_FILTER_PORTS,
    auto_len: usize = 0,
    auto_enabled: bool = true,
    process_name: []const u8 = DEFAULT_PROCESS_NAME,
    litenet: bool = true,
    all_udp: bool = false,
    last_refresh_ns: i128 = 0,
    verbose_once: bool = true, // extra detail on first refresh + when still empty

    fn setManual(self: *PortFilter, ports: []const u16) void {
        self.manual_len = 0;
        for (ports) |p| {
            if (p == 0) continue;
            if (self.manual_len >= MAX_FILTER_PORTS) break;
            var dup = false;
            for (self.manual[0..self.manual_len]) |m| {
                if (m == p) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                self.manual[self.manual_len] = p;
                self.manual_len += 1;
            }
        }
        if (self.manual_len > 0) {
            var msg_buf: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&msg_buf);
            w.writeAll("Port filter: manual UDP ports ") catch {};
            for (self.manual[0..self.manual_len], 0..) |p, i| {
                if (i > 0) w.writeAll(",") catch {};
                w.print("{d}", .{p}) catch {};
            }
            std.log.info("{s}", .{w.buffered()});
        }
    }

    fn hasPort(self: *const PortFilter, port: u16) bool {
        for (self.manual[0..self.manual_len]) |p| {
            if (p == port) return true;
        }
        for (self.auto[0..self.auto_len]) |p| {
            if (p == port) return true;
        }
        return false;
    }

    fn portCount(self: *const PortFilter) usize {
        return self.manual_len + self.auto_len;
    }

    fn acceptWithReason(self: *PortFilter, sport: u16, dport: u16, payload: []const u8) u8 {
        if (self.all_udp) {
            if (self.litenet and !looksLikeLiteNet(payload)) return 3;
            return 0;
        }
        if (self.auto_enabled) {
            const now = monoNowNs();
            if (now - self.last_refresh_ns >= PORT_REFRESH_NS) {
                self.refreshAuto();
                self.last_refresh_ns = now;
            }
        }
        if (self.portCount() == 0) return 1;
        if (!(self.hasPort(sport) or self.hasPort(dport))) return 2;
        if (self.litenet and !looksLikeLiteNet(payload)) return 3;
        return 0;
    }

    /// Returns true if pid matches process_name via comm, cmdline, or exe.
    fn pidMatchesName(self: *PortFilter, pid: u32, log_near_miss: bool) bool {
        var path_buf: [96]u8 = undefined;
        var data_buf: [512]u8 = undefined;

        // 1) /proc/pid/comm  (Wine: usually "SpiritVale.exe")
        {
            const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/comm", .{pid}) catch return false;
            if (readProcPath(path, &data_buf)) |comm| {
                const trimmed = std.mem.trim(u8, comm, " \t\r\n");
                if (containsIgnoreCase(trimmed, self.process_name)) {
                    if (self.verbose_once) {
                        std.log.info("[discover] MATCH pid={d} via comm='{s}'", .{ pid, trimmed });
                    }
                    return true;
                }
                if (log_near_miss and containsIgnoreCase(trimmed, "spirit")) {
                    std.log.info("[discover] near-miss pid={d} comm='{s}' (wanted '{s}')", .{ pid, trimmed, self.process_name });
                }
            } else if (self.verbose_once and log_near_miss) {
                // only spam for interesting pids — skip
            }
        }

        // 2) /proc/pid/cmdline
        {
            const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/cmdline", .{pid}) catch return false;
            if (readProcPath(path, &data_buf)) |cmdline| {
                if (containsIgnoreCase(cmdline, self.process_name)) {
                    if (self.verbose_once) {
                        // cmdline is NUL-separated; show printable preview
                        var preview: [80]u8 = undefined;
                        const n = @min(cmdline.len, preview.len);
                        for (cmdline[0..n], 0..) |c, i| {
                            preview[i] = if (c == 0 or c < 32) ' ' else c;
                        }
                        std.log.info("[discover] MATCH pid={d} via cmdline~'{s}'", .{ pid, preview[0..n] });
                    }
                    return true;
                }
            }
        }

        // 3) /proc/pid/exe
        {
            const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid}) catch return false;
            if (readlinkProcPath(path, &data_buf)) |exe| {
                if (containsIgnoreCase(exe, self.process_name)) {
                    if (self.verbose_once) {
                        std.log.info("[discover] MATCH pid={d} via exe='{s}'", .{ pid, exe });
                    }
                    return true;
                }
            }
        }

        return false;
    }

    fn refreshAuto(self: *PortFilter) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        const verbose = self.verbose_once or (self.auto_len == 0);
        if (verbose) {
            std.log.info("[discover] scanning /proc for process name containing '{s}'…", .{self.process_name});
        }

        var new_ports: [MAX_FILTER_PORTS]u16 = .{0} ** MAX_FILTER_PORTS;
        var new_len: usize = 0;

        var inode_set: [1024]u64 = undefined;
        var inode_len: usize = 0;
        var process_matches: u64 = 0;
        var pids_scanned: u64 = 0;
        var spirit_named: u64 = 0; // any comm containing "spirit" (case-insensitive)

        var proc_dir = Io.Dir.openDirAbsolute(self.io, "/proc", .{ .iterate = true }) catch |err| {
            std.log.err("[discover] cannot open /proc: {s}", .{@errorName(err)});
            return;
        };
        defer proc_dir.close(self.io);

        var it = proc_dir.iterate();
        while (true) {
            const maybe_entry = it.next(self.io) catch |err| {
                std.log.warn("[discover] /proc iterate error: {s}", .{@errorName(err)});
                break;
            };
            const entry = maybe_entry orelse break;
            if (entry.kind != .directory) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            pids_scanned += 1;

            // Count near-misses for debugging Proton naming
            var comm_buf: [64]u8 = undefined;
            var path_buf: [64]u8 = undefined;
            const cpath = std.fmt.bufPrint(&path_buf, "/proc/{d}/comm", .{pid}) catch continue;
            if (readProcPath(cpath, &comm_buf)) |comm| {
                const t = std.mem.trim(u8, comm, " \t\r\n");
                if (containsIgnoreCase(t, "spirit")) spirit_named += 1;
            }

            if (!self.pidMatchesName(pid, verbose and spirit_named < 8)) continue;
            process_matches += 1;

            // Collect socket inodes from /proc/pid/fd
            var fd_path_buf: [64]u8 = undefined;
            const fd_path = std.fmt.bufPrint(&fd_path_buf, "/proc/{d}/fd", .{pid}) catch continue;
            var fd_dir = Io.Dir.openDirAbsolute(self.io, fd_path, .{ .iterate = true }) catch |err| {
                std.log.warn("[discover] pid={d}: cannot open fd dir: {s} (need root?)", .{ pid, @errorName(err) });
                continue;
            };
            defer fd_dir.close(self.io);

            var sockets_found: u64 = 0;
            var fd_it = fd_dir.iterate();
            while (fd_it.next(self.io) catch null) |fd_ent| {
                var link_buf: [128]u8 = undefined;
                var full_fd: [96]u8 = undefined;
                const full = std.fmt.bufPrint(&full_fd, "/proc/{d}/fd/{s}", .{ pid, fd_ent.name }) catch continue;
                const link = readlinkProcPath(full, &link_buf) orelse continue;
                if (!std.mem.startsWith(u8, link, "socket:[")) continue;
                if (!std.mem.endsWith(u8, link, "]")) continue;
                const num = link["socket:[".len .. link.len - 1];
                const inode = std.fmt.parseInt(u64, num, 10) catch continue;
                sockets_found += 1;
                if (inode_len < inode_set.len) {
                    // dedupe inode
                    var exists = false;
                    for (inode_set[0..inode_len]) |ino| {
                        if (ino == inode) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists) {
                        inode_set[inode_len] = inode;
                        inode_len += 1;
                    }
                }
            }
            if (verbose) {
                std.log.info("[discover] pid={d}: socket fds={d} (unique inodes so far={d})", .{ pid, sockets_found, inode_len });
            }
        }

        stats.process_hits = process_matches;

        if (verbose) {
            std.log.info(
                "[discover] scan done: pids={d} spirit-named-comm={d} matches='{s}'={d} socket-inodes={d}",
                .{ pids_scanned, spirit_named, self.process_name, process_matches, inode_len },
            );
        }

        if (process_matches == 0) {
            if (spirit_named > 0) {
                std.log.warn(
                    \\[discover] Found {d} process(es) with 'spirit' in comm, but none matched '{s}'.
                    \\  Try:  --process-name SpiritVale.exe
                    \\  Or list:  cat /proc/$(pgrep -f SpiritVale | head -1)/comm
                , .{ spirit_named, self.process_name });
            } else {
                std.log.warn(
                    \\[discover] No process matched '{s}' (scanned {d} pids).
                    \\  Is the game running?  ps aux | grep -i spirit
                    \\  Proton binary is often:  SpiritVale.exe
                , .{ self.process_name, pids_scanned });
            }
            self.auto_len = 0;
            // keep verbose until we succeed once
            return;
        }

        if (inode_len == 0) {
            std.log.warn(
                \\[discover] Matched {d} process(es) but found 0 socket fds.
                \\  Enter the game world so UDP sockets open. Check: sudo ss -ulnp | grep -i spirit
            , .{process_matches});
            self.auto_len = 0;
            return;
        }

        // Map inodes → local UDP ports via /proc/net/udp{,6}
        self.collectPortsFromTable("/proc/net/udp", inode_set[0..inode_len], &new_ports, &new_len, verbose);
        self.collectPortsFromTable("/proc/net/udp6", inode_set[0..inode_len], &new_ports, &new_len, verbose);

        var changed = new_len != self.auto_len;
        if (!changed) {
            for (new_ports[0..new_len], 0..) |p, i| {
                if (self.auto[i] != p) {
                    changed = true;
                    break;
                }
            }
        }
        @memcpy(self.auto[0..new_len], new_ports[0..new_len]);
        self.auto_len = new_len;

        if (new_len == 0) {
            std.log.warn(
                \\[discover] {d} socket inodes but 0 matched in /proc/net/udp[6].
                \\  Inodes may be in a different netns. Prefer manual:  --ports … from ss
            , .{inode_len});
            return;
        }

        if (changed or verbose) {
            var msg_buf: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&msg_buf);
            w.writeAll("[discover] auto UDP ports: ") catch {};
            for (new_ports[0..new_len], 0..) |p, i| {
                if (i > 0) w.writeAll(",") catch {};
                w.print("{d}", .{p}) catch {};
            }
            std.log.info("{s}", .{w.buffered()});
            stats.warned_no_ports = false;
            stats.warned_all_filtered = false;
            self.verbose_once = false; // quiet after first success
        }
    }

    fn collectPortsFromTable(
        self: *PortFilter,
        path: []const u8,
        inodes: []const u64,
        out_ports: *[MAX_FILTER_PORTS]u16,
        out_len: *usize,
        verbose: bool,
    ) void {
        _ = self;
        // Read via linux open/read — avoid Io absolute-path quirks
        var file_buf: [512 * 1024]u8 = undefined;
        const data = readProcPath(path, &file_buf) orelse {
            std.log.warn("[discover] cannot read {s}", .{path});
            return;
        };

        var matched_rows: u64 = 0;
        var lines = std.mem.splitScalar(u8, data, '\n');
        _ = lines.next(); // header
        while (lines.next()) |line| {
            if (line.len < 10) continue;
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            _ = fields.next(); // sl
            const local = fields.next() orelse continue;
            const colon = std.mem.lastIndexOfScalar(u8, local, ':') orelse continue;
            const port = std.fmt.parseInt(u16, local[colon + 1 ..], 16) catch continue;
            if (port == 0) continue;

            var all = std.mem.tokenizeAny(u8, line, " \t");
            var idx: usize = 0;
            var inode_val: ?u64 = null;
            while (all.next()) |f| : (idx += 1) {
                if (idx == 9) {
                    inode_val = std.fmt.parseInt(u64, f, 10) catch null;
                    break;
                }
            }
            const inode = inode_val orelse continue;
            var match = false;
            for (inodes) |ino| {
                if (ino == inode) {
                    match = true;
                    break;
                }
            }
            if (!match) continue;
            matched_rows += 1;

            var exists = false;
            for (out_ports.*[0..out_len.*]) |p| {
                if (p == port) {
                    exists = true;
                    break;
                }
            }
            if (!exists and out_len.* < MAX_FILTER_PORTS) {
                out_ports.*[out_len.*] = port;
                out_len.* += 1;
                if (verbose) {
                    std.log.info("[discover] {s}: inode={d} → local UDP port {d}", .{ path, inode, port });
                }
            }
        }
        if (verbose) {
            std.log.info("[discover] {s}: matched {d} rows → running port count {d}", .{ path, matched_rows, out_len.* });
        }
    }
};

var port_filter: PortFilter = .{};

const WsSlot = struct {
    ws: *std.http.Server.WebSocket,
    active: bool = true,
};

const OutputHub = struct {
    io: Io = undefined,
    allocator: std.mem.Allocator = undefined,
    file: ?Io.File = null,
    path_buf: [512]u8 = undefined,
    path_len: usize = 0,
    to_stdout: bool = false,
    stdout_buf: [4096]u8 = undefined,
    stdout_writer: ?Io.File.Writer = null,
    start_ns: i128 = 0,
    events: u64 = 0,
    bytes_payload: u64 = 0,
    line_buf: [96 * 1024]u8 = undefined,
    ws_mutex: Io.Mutex = .init,
    ws_slots: [MAX_WS_CLIENTS]?WsSlot = .{null} ** MAX_WS_CLIENTS,
    ws_count: usize = 0,
    ws_send_ok: u64 = 0,
    ws_send_fail: u64 = 0,

    fn path(self: *const OutputHub) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn openFile(self: *OutputHub, io: Io, dir_path: ?[]const u8, override_name: ?[]const u8) !void {
        self.io = io;
        const utc = utcComponents();

        if (override_name) |name| {
            if (dir_path) |dir| {
                if (!isPathSafe(name) or !hasAllowedExt(name)) return error.UnsafePath;
                const full = try std.fmt.bufPrint(&self.path_buf, "{s}/{s}", .{ dir, name });
                self.path_len = full.len;
            } else {
                if (std.mem.indexOf(u8, name, "..") != null) return error.UnsafePath;
                const full = try std.fmt.bufPrint(&self.path_buf, "{s}", .{name});
                self.path_len = full.len;
            }
        } else {
            const auto = try std.fmt.bufPrint(&self.path_buf, "sv-{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z{s}", .{
                utc.year, utc.month, utc.day, utc.hour, utc.min, utc.sec, ALLOWED_REPLAY_EXT,
            });
            if (dir_path) |dir| {
                var tmp: [128]u8 = undefined;
                @memcpy(tmp[0..auto.len], auto);
                const full = try std.fmt.bufPrint(&self.path_buf, "{s}/{s}", .{ dir, tmp[0..auto.len] });
                self.path_len = full.len;
            } else {
                self.path_len = auto.len;
            }
        }

        if (dir_path) |dir| {
            Io.Dir.cwd().createDirPath(io, dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => {
                    std.log.err("Cannot create log dir '{s}': {s}", .{ dir, @errorName(err) });
                    return err;
                },
            };
        }

        self.file = Io.Dir.cwd().createFile(io, self.path(), .{}) catch |err| {
            std.log.err("Cannot create replay file '{s}': {s}", .{ self.path(), @errorName(err) });
            return err;
        };
        self.start_ns = monoNowNs();
        self.events = 0;
        self.bytes_payload = 0;

        var iso_buf: [32]u8 = undefined;
        const iso = try std.fmt.bufPrint(&iso_buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
            utc.year, utc.month, utc.day, utc.hour, utc.min, utc.sec,
        });

        const header = try std.fmt.bufPrint(&self.line_buf,
            \\{{"type":"header","format":"sv-replay","formatVersion":"{s}","createdUtc":"{s}","game":"Spirit Vale","assumedTickMs":{d:.3},"ticksPerSecond":{d:.0},"payload":"udp","encoding":"base64","direction":{{"in":"to local host","out":"from local host"}},"note":"JSON Lines."}}
            \\
        , .{ REPLAY_FORMAT_VERSION, iso, ASSUMED_TICK_MS, TICKS_PER_SECOND });

        try self.file.?.writeStreamingAll(io, header);
        if (self.to_stdout) try self.writeStdout(header);
        self.broadcastLine(header);
    }

    fn enableStdout(self: *OutputHub, io: Io) void {
        self.io = io;
        self.to_stdout = true;
        self.stdout_writer = Io.File.stdout().writer(io, &self.stdout_buf);
        if (self.start_ns == 0) self.start_ns = monoNowNs();
    }

    fn writeStdout(self: *OutputHub, line: []const u8) !void {
        if (self.stdout_writer) |*w| {
            try w.interface.writeAll(line);
            try w.interface.flush();
        }
    }

    fn addWs(self: *OutputHub, ws: *std.http.Server.WebSocket) bool {
        self.ws_mutex.lockUncancelable(self.io);
        defer self.ws_mutex.unlock(self.io);
        for (&self.ws_slots) |*slot| {
            if (slot.* == null) {
                slot.* = .{ .ws = ws, .active = true };
                self.ws_count += 1;
                return true;
            }
        }
        return false;
    }

    fn removeWs(self: *OutputHub, ws: *std.http.Server.WebSocket) void {
        self.ws_mutex.lockUncancelable(self.io);
        defer self.ws_mutex.unlock(self.io);
        for (&self.ws_slots) |*slot| {
            if (slot.*) |*s| {
                if (s.ws == ws) {
                    slot.* = null;
                    if (self.ws_count > 0) self.ws_count -= 1;
                    return;
                }
            }
        }
    }

    fn broadcastLine(self: *OutputHub, line: []const u8) void {
        if (self.ws_count == 0) return;
        self.ws_mutex.lockUncancelable(self.io);
        defer self.ws_mutex.unlock(self.io);
        const payload = if (line.len > 0 and line[line.len - 1] == '\n') line[0 .. line.len - 1] else line;
        for (&self.ws_slots) |*slot| {
            if (slot.*) |*s| {
                if (!s.active) continue;
                s.ws.writeMessage(payload, .text) catch |err| {
                    self.ws_send_fail += 1;
                    std.log.warn("WebSocket write failed: {s}", .{@errorName(err)});
                    s.active = false;
                    slot.* = null;
                    if (self.ws_count > 0) self.ws_count -= 1;
                    continue;
                };
                self.ws_send_ok += 1;
            }
        }
    }

    fn record(self: *OutputHub, dir: []const u8, payload: []const u8) void {
        if (payload.len == 0) return;
        if (self.start_ns == 0) self.start_ns = monoNowNs();

        const t_ms = @as(f64, @floatFromInt(monoNowNs() - self.start_ns)) / 1e6;
        const b64_len = std.base64.standard.Encoder.calcSize(payload.len);
        if (80 + b64_len + 3 > self.line_buf.len) return;

        const prefix = std.fmt.bufPrint(self.line_buf[0..80], "{{\"t\":{d:.3},\"d\":\"{s}\",\"n\":{d},\"b64\":\"", .{
            t_ms, dir, payload.len,
        }) catch return;

        _ = std.base64.standard.Encoder.encode(self.line_buf[prefix.len..][0..b64_len], payload);
        const end = prefix.len + b64_len;
        self.line_buf[end] = '"';
        self.line_buf[end + 1] = '}';
        self.line_buf[end + 2] = '\n';
        const line = self.line_buf[0 .. end + 3];

        if (self.file) |*f| f.writeStreamingAll(self.io, line) catch {};
        if (self.to_stdout) self.writeStdout(line) catch {};
        self.broadcastLine(line);
        self.events += 1;
        self.bytes_payload += payload.len;
        stats.accepted += 1;
        stats.last_accepted_ns = monoNowNs();
    }

    fn close(self: *OutputHub) void {
        if (self.start_ns == 0) return;
        const footer = std.fmt.bufPrint(&self.line_buf,
            \\{{"type":"footer","events":{d},"payloadBytes":{d},"durationMs":{d:.1}}}
            \\
        , .{
            self.events,
            self.bytes_payload,
            @as(f64, @floatFromInt(monoNowNs() - self.start_ns)) / 1e6,
        }) catch {
            if (self.file) |*f| f.close(self.io);
            return;
        };
        if (self.file) |*f| {
            f.writeStreamingAll(self.io, footer) catch {};
            f.close(self.io);
            self.file = null;
            std.log.info("Replay saved: {s}  ({d} events, {d} payload bytes)", .{
                self.path(), self.events, self.bytes_payload,
            });
        }
        if (self.to_stdout) self.writeStdout(footer) catch {};
        self.broadcastLine(footer);
        self.ws_mutex.lockUncancelable(self.io);
        defer self.ws_mutex.unlock(self.io);
        for (&self.ws_slots) |*slot| slot.* = null;
        self.ws_count = 0;
    }
};

var hub: OutputHub = .{};

const HttpCtx = struct {
    io: Io,
    allocator: std.mem.Allocator,
    static_dir: []const u8,
    sessions_dir: ?[]const u8,
    port: u16,
    bind: []const u8,
};

fn httpServerThread(ctx: HttpCtx) void {
    const addr = net.IpAddress.parse(ctx.bind, ctx.port) catch |err| {
        std.log.err("HTTP bind resolve failed: {s}", .{@errorName(err)});
        return;
    };
    var server = addr.listen(ctx.io, .{ .reuse_address = true }) catch |err| {
        std.log.err("HTTP listen failed on {s}:{d}: {s}", .{ ctx.bind, ctx.port, @errorName(err) });
        return;
    };
    defer server.deinit(ctx.io);
    std.log.info("HTTP server on http://{s}:{d}/  (WS: ws://{s}:{d}/ws)", .{
        ctx.bind, ctx.port, ctx.bind, ctx.port,
    });
    while (true) {
        const stream = server.accept(ctx.io) catch |err| {
            std.log.warn("HTTP accept: {s}", .{@errorName(err)});
            continue;
        };
        const t = std.Thread.spawn(.{}, handleHttpConn, .{ stream, ctx }) catch {
            stream.close(ctx.io);
            continue;
        };
        t.detach();
    }
}

fn handleHttpConn(stream: net.Stream, ctx: HttpCtx) void {
    defer stream.close(ctx.io);
    var recv_buffer: [8192]u8 = undefined;
    var send_buffer: [8192]u8 = undefined;
    var stream_reader = stream.reader(ctx.io, &recv_buffer);
    var stream_writer = stream.writer(ctx.io, &send_buffer);
    var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
    while (http_server.reader.state == .ready) {
        var request = http_server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => {
                std.log.warn("HTTP receiveHead: {s}", .{@errorName(err)});
                return;
            },
        };
        switch (request.upgradeRequested()) {
            .other => return,
            .websocket => |key| {
                if (!std.mem.eql(u8, pathFromTarget(request.head.target), "/ws")) {
                    request.respond("WebSocket only on /ws\n", .{ .status = .not_found }) catch {};
                    return;
                }
                var ws = request.respondWebSocket(.{ .key = key orelse "" }) catch |err| {
                    std.log.warn("WebSocket handshake failed: {s}", .{@errorName(err)});
                    return;
                };
                if (!hub.addWs(&ws)) {
                    std.log.warn("Too many WebSocket clients", .{});
                    return;
                }
                std.log.info("WebSocket client connected ({d} total)", .{hub.ws_count});
                defer {
                    hub.removeWs(&ws);
                    std.log.info("WebSocket client disconnected ({d} remaining)", .{hub.ws_count});
                }
                while (true) {
                    const msg = ws.readSmallMessage() catch break;
                    if (msg.opcode == .connection_close) break;
                }
                return;
            },
            .none => {
                serveHttpRequest(&request, ctx) catch |err| {
                    std.log.warn("HTTP serve error: {s}", .{@errorName(err)});
                    return;
                };
            },
        }
    }
}

fn pathFromTarget(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |q| return target[0..q];
    return target;
}

fn serveHttpRequest(request: *std.http.Server.Request, ctx: HttpCtx) !void {
    const method = request.head.method;
    const path = pathFromTarget(request.head.target);
    if (method != .GET and method != .HEAD) {
        try request.respond("Method Not Allowed\n", .{ .status = .method_not_allowed });
        return;
    }
    if (std.mem.eql(u8, path, "/api/sessions")) {
        try serveSessionList(request, ctx);
        return;
    }
    if (std.mem.startsWith(u8, path, "/api/sessions/")) {
        try serveSessionFile(request, ctx, path["/api/sessions/".len..]);
        return;
    }
    if (std.mem.eql(u8, path, "/api/status")) {
        try serveStatus(request);
        return;
    }
    try serveStatic(request, ctx, path);
}

fn serveStatus(request: *std.http.Server.Request) !void {
    var buf: [1024]u8 = undefined;
    const body = try std.fmt.bufPrint(&buf,
        \\{{"udpSeen":{d},"accepted":{d},"rejectNoPorts":{d},"rejectPort":{d},"rejectLitenet":{d},"filterPorts":{d},"wsClients":{d},"wsSendOk":{d},"wsSendFail":{d},"processHits":{d},"events":{d}}}
        \\
    , .{
        stats.udp_seen,
        stats.accepted,
        stats.rejected_no_ports,
        stats.rejected_port,
        stats.rejected_litenet,
        port_filter.portCount(),
        hub.ws_count,
        hub.ws_send_ok,
        hub.ws_send_fail,
        stats.process_hits,
        hub.events,
    });
    try request.respond(body, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    });
}

fn serveSessionList(request: *std.http.Server.Request, ctx: HttpCtx) !void {
    const dir_path = ctx.sessions_dir orelse {
        try request.respond("{\"error\":\"sessions_dir not configured\"}\n", .{
            .status = .service_unavailable,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json; charset=utf-8" }},
        });
        return;
    };
    var dir = Io.Dir.cwd().openDir(ctx.io, dir_path, .{ .iterate = true }) catch {
        try request.respond("{\"sessions\":[]}\n", .{
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json; charset=utf-8" }},
        });
        return;
    };
    defer dir.close(ctx.io);
    var list_buf: [32 * 1024]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&list_buf);
    try writer.writeAll("{\"sessions\":[");
    var first = true;
    var it = dir.iterate();
    while (try it.next(ctx.io)) |entry| {
        if (entry.kind != .file) continue;
        if (!hasAllowedExt(entry.name) or !isPathSafe(entry.name)) continue;
        if (!first) try writer.writeAll(",");
        first = false;
        try writer.print("\"{s}\"", .{entry.name});
    }
    try writer.writeAll("]}\n");
    try request.respond(writer.buffered(), .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    });
}

fn serveSessionFile(request: *std.http.Server.Request, ctx: HttpCtx, name: []const u8) !void {
    const dir_path = ctx.sessions_dir orelse {
        try request.respond("sessions_dir not configured\n", .{ .status = .service_unavailable });
        return;
    };
    if (!isPathSafe(name) or !hasAllowedExt(name)) {
        try request.respond("Forbidden\n", .{ .status = .forbidden });
        return;
    }
    var path_buf: [512]u8 = undefined;
    const full = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir_path, name }) catch {
        try request.respond("Bad path\n", .{ .status = .bad_request });
        return;
    };
    const content = Io.Dir.readFileAlloc(Io.Dir.cwd(), ctx.io, full, ctx.allocator, .limited(MAX_SESSION_FILE)) catch {
        try request.respond("Not found\n", .{ .status = .not_found });
        return;
    };
    defer ctx.allocator.free(content);
    try request.respond(content, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/x-ndjson; charset=utf-8" },
            .{ .name = "access-control-allow-origin", .value = "*" },
        },
    });
}

fn serveStatic(request: *std.http.Server.Request, ctx: HttpCtx, url_path: []const u8) !void {
    const rel = blk: {
        if (url_path.len == 0 or std.mem.eql(u8, url_path, "/")) break :blk "index.html";
        if (url_path[0] == '/') break :blk url_path[1..];
        break :blk url_path;
    };
    if (std.mem.indexOf(u8, rel, "..") != null) {
        try request.respond("Forbidden\n", .{ .status = .forbidden });
        return;
    }
    var path_buf: [512]u8 = undefined;
    const full = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ ctx.static_dir, rel }) catch {
        try request.respond("Bad path\n", .{ .status = .bad_request });
        return;
    };
    const content = Io.Dir.readFileAlloc(Io.Dir.cwd(), ctx.io, full, ctx.allocator, .limited(MAX_STATIC_FILE)) catch {
        if (std.mem.eql(u8, rel, "index.html")) {
            const placeholder =
                \\<!DOCTYPE html>
                \\<html><head><meta charset="utf-8"><title>LiteNet Capture</title></head>
                \\<body>
                \\<h1>LiteNet Capture</h1>
                \\<p>This a debug / development UI intended for troubleshooting & developers. You can provide a better user experience with a custom index.html file; just drop it here ./static/index.html. You can use this file as a template & make your own, or use the provided example from the Spirit Vale Replay Companion project.</p>
                \\<p>WS: <code id="wsurl"></code></p>
                \\<pre id="st"></pre>
                \\<pre id="log"></pre>
                \\<script>
                \\const wsUrl = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
                \\document.getElementById('wsurl').textContent = wsUrl;
                \\const log = document.getElementById('log');
                \\const st = document.getElementById('st');
                \\const ws = new WebSocket(wsUrl);
                \\ws.onmessage = (e) => { log.textContent += e.data + '\n'; };
                \\ws.onopen = () => { log.textContent += '[ws connected]\n'; };
                \\ws.onclose = () => { log.textContent += '[ws disconnected]\n'; };
                \\setInterval(() => fetch('/api/status').then(r=>r.json()).then(j=>{
                \\  st.textContent = JSON.stringify(j,null,2);
                \\}).catch(()=>{}), 2000);
                \\</script>
                \\</body></html>
            ;
            try request.respond(placeholder, .{
                .extra_headers = &.{.{ .name = "content-type", .value = "text/html; charset=utf-8" }},
            });
            return;
        }
        try request.respond("Not found\n", .{ .status = .not_found });
        return;
    };
    defer ctx.allocator.free(content);
    try request.respond(content, .{
        .extra_headers = &.{.{ .name = "content-type", .value = mimeForPath(rel) }},
    });
}

fn tryOpenBrowser(io: Io, url: []const u8) void {
    const argv = [_][]const u8{ "xdg-open", url };
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch {
        std.log.warn("xdg-open failed — open {s} manually", .{url});
        return;
    };
    _ = child.wait(io) catch {};
}

fn check(rc: usize, comptime what: []const u8) !void {
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |err| {
            std.log.err("{s} failed: {s}", .{ what, @tagName(err) });
            if (std.mem.eql(u8, what, "socket") or std.mem.eql(u8, what, "bind")) {
                std.log.err("AF_PACKET needs root/CAP_NET_RAW — use sudo", .{});
            }
            return error.SyscallFailed;
        },
    }
}

fn listInterfaces(io: Io, allocator: std.mem.Allocator) ![]const []const u8 {
    var dir = try Io.Dir.openDirAbsolute(io, "/sys/class/net", .{ .iterate = true });
    defer dir.close(io);
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |n| allocator.free(n);
        list.deinit(allocator);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory and entry.kind != .sym_link) continue;
        if (std.mem.eql(u8, entry.name, "bonding_masters")) continue;
        try list.append(allocator, try allocator.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, list.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    return try list.toOwnedSlice(allocator);
}

fn freeInterfaces(allocator: std.mem.Allocator, list: []const []const u8) void {
    for (list) |n| allocator.free(n);
    allocator.free(list);
}

fn printHelp(stdout: anytype) !void {
    try stdout.writeAll(
        \\
        \\Spirit Vale UDP capture
        \\
        \\  -i <iface>   --ports <list>   --process-name <str>
        \\  --no-auto-ports  --no-litenet-filter  --all-udp
        \\  -s  -d <dir>  -w  -p <port>  --open  -h
        \\
        \\Watch [discover] log lines for port auto-detection (Proton/Wine).
        \\
    );
}

fn parsePortList(cfg: *Config, list: []const u8) !void {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |part| {
        const p = std.mem.trim(u8, part, " \t");
        if (p.len == 0) continue;
        const port = try std.fmt.parseInt(u16, p, 10);
        if (port == 0) continue;
        if (cfg.ports_len >= MAX_FILTER_PORTS) return error.TooManyPorts;
        cfg.ports[cfg.ports_len] = port;
        cfg.ports_len += 1;
    }
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !Config {
    var cfg: Config = .{};
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            cfg.help = true;
        } else if (std.mem.eql(u8, a, "-s") or std.mem.eql(u8, a, "--stdout")) {
            cfg.stdout = true;
        } else if (std.mem.eql(u8, a, "-w") or std.mem.eql(u8, a, "--http")) {
            cfg.http = true;
        } else if (std.mem.eql(u8, a, "--no-file")) {
            cfg.no_file = true;
        } else if (std.mem.eql(u8, a, "--open")) {
            cfg.open_browser = true;
        } else if (std.mem.eql(u8, a, "-y") or std.mem.eql(u8, a, "--yes")) {
            cfg.force_yes = true;
        } else if (std.mem.eql(u8, a, "--no-auto-ports")) {
            cfg.auto_ports = false;
        } else if (std.mem.eql(u8, a, "--no-litenet-filter")) {
            cfg.litenet_filter = false;
        } else if (std.mem.eql(u8, a, "--all-udp")) {
            cfg.all_udp = true;
        } else if (std.mem.eql(u8, a, "-i") or std.mem.eql(u8, a, "--interface")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.interface = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-d") or std.mem.eql(u8, a, "--dir")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.log_dir = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-f") or std.mem.eql(u8, a, "--file")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.log_file = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "-p") or std.mem.eql(u8, a, "--port")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.http_port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, a, "--bind")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.http_bind = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "--static-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.static_dir = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "--sessions-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.sessions_dir = try allocator.dupe(u8, args[i]);
        } else if (std.mem.eql(u8, a, "--ports")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            try parsePortList(&cfg, args[i]);
        } else if (std.mem.eql(u8, a, "--process-name")) {
            i += 1;
            if (i >= args.len) return error.MissingArg;
            cfg.process_name = try allocator.dupe(u8, args[i]);
        } else {
            std.log.warn("Unknown argument: {s}", .{a});
            return error.UnknownArg;
        }
    }
    return cfg;
}

fn readLine(io: Io, buf: []u8) ![]const u8 {
    var stdin_reader = Io.File.stdin().reader(io, buf);
    const line = try stdin_reader.interface.takeDelimiterExclusive('\n');
    return std.mem.trim(u8, line, " \t\r");
}

fn promptYesNo(io: Io, stdout: anytype, question: []const u8, default_yes: bool) !bool {
    const hint = if (default_yes) "Y/n" else "y/N";
    try stdout.print("{s} [{s}]: ", .{ question, hint });
    try stdout.flush();
    var buf: [64]u8 = undefined;
    const line = readLine(io, &buf) catch return default_yes;
    if (line.len == 0) return default_yes;
    if (line[0] == 'y' or line[0] == 'Y') return true;
    if (line[0] == 'n' or line[0] == 'N') return false;
    return default_yes;
}

fn buildLaunchCommand(cfg: *const Config, buf: []u8) ![]const u8 {
    var w: std.Io.Writer = .fixed(buf);
    try w.writeAll("sudo zig run src/main.zig --");
    if (cfg.interface) |iface| try w.print(" -i {s}", .{iface});
    if (cfg.log_dir) |d| try w.print(" -d {s}", .{d});
    if (cfg.sessions_dir) |d| try w.print(" --sessions-dir {s}", .{d});
    if (cfg.stdout) try w.writeAll(" -s");
    if (cfg.http) {
        try w.writeAll(" -w");
        if (cfg.http_port != DEFAULT_HTTP_PORT) try w.print(" -p {d}", .{cfg.http_port});
        if (cfg.open_browser) try w.writeAll(" --open");
    }
    if (cfg.no_file) try w.writeAll(" --no-file");
    if (cfg.ports_len > 0) {
        try w.writeAll(" --ports ");
        for (cfg.ports[0..cfg.ports_len], 0..) |p, i| {
            if (i > 0) try w.writeAll(",");
            try w.print("{d}", .{p});
        }
    }
    if (!cfg.auto_ports) try w.writeAll(" --no-auto-ports");
    if (!cfg.litenet_filter) try w.writeAll(" --no-litenet-filter");
    if (cfg.all_udp) try w.writeAll(" --all-udp");
    if (!std.mem.eql(u8, cfg.process_name, DEFAULT_PROCESS_NAME))
        try w.print(" --process-name {s}", .{cfg.process_name});
    return w.buffered();
}

fn writeLaunchScript(io: Io, cfg: *const Config) !void {
    var cmd_buf: [1024]u8 = undefined;
    const cmd = try buildLaunchCommand(cfg, &cmd_buf);
    var script_buf: [2048]u8 = undefined;
    const script = try std.fmt.bufPrint(&script_buf,
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\cd "$(dirname "$0")"
        \\{s}
        \\
    , .{cmd});
    const file = try Io.Dir.cwd().createFile(io, "ln-capture.sh", .{});
    defer file.close(io);
    try file.writeStreamingAll(io, script);
}

fn runWizard(io: Io, allocator: std.mem.Allocator, cfg: *Config, interfaces: []const []const u8) !void {
    var stdout_buf: [2048]u8 = undefined;
    var stdout_writer = Io.File.stdout().writer(io, &stdout_buf);
    const stdout = &stdout_writer.interface;

    try stdout.writeAll("\n=== LiteNet capture — setup wizard ===\n\n");

    if (cfg.interface == null) {
        try stdout.writeAll("Available network interfaces:\n\n");
        for (interfaces, 0..) |name, idx| {
            try stdout.print("  [{d}] {s}\n", .{ idx + 1, name });
        }
        try stdout.print("\nEnter number (1-{d}) or interface name: ", .{interfaces.len});
        try stdout.flush();
        var buf: [128]u8 = undefined;
        const line = try readLine(io, &buf);
        if (std.fmt.parseInt(usize, line, 10)) |choice| {
            if (choice < 1 or choice > interfaces.len) return error.InvalidChoice;
            cfg.interface = try allocator.dupe(u8, interfaces[choice - 1]);
        } else |_| {
            cfg.interface = try allocator.dupe(u8, line);
        }
        try stdout.print("Selected: {s}\n\n", .{cfg.interface.?});
        try stdout.flush();
    }

    if (!cfg.stdout and cfg.log_dir == null and cfg.log_file == null and !cfg.no_file and !cfg.http) {
        if (try promptYesNo(io, stdout, "Write replay file to disk?", true)) {
            try stdout.writeAll("Directory [./replays]: ");
            try stdout.flush();
            var buf: [256]u8 = undefined;
            const line = readLine(io, &buf) catch "./replays";
            const dir = if (line.len == 0) "./replays" else line;
            cfg.log_dir = try allocator.dupe(u8, dir);
            if (cfg.sessions_dir == null) cfg.sessions_dir = try allocator.dupe(u8, dir);
        } else {
            cfg.no_file = true;
        }
        cfg.stdout = try promptYesNo(io, stdout, "Stream JSONL to stdout?", false);
        cfg.http = try promptYesNo(io, stdout, "Start HTTP + WebSocket server?", true);
        if (cfg.http) {
            cfg.open_browser = try promptYesNo(io, stdout, "Open browser?", true);
        }
    }

    cfg.auto_ports = try promptYesNo(io, stdout, "Auto-discover game UDP ports?", true);
    if (cfg.auto_ports) {
        try stdout.writeAll("Process name substring [SpiritVale]: ");
        try stdout.flush();
        var buf: [128]u8 = undefined;
        const line = readLine(io, &buf) catch "";
        if (line.len > 0) cfg.process_name = try allocator.dupe(u8, line);
    }
    try stdout.writeAll("Optional fixed ports (comma-separated, empty skip): ");
    try stdout.flush();
    {
        var buf: [256]u8 = undefined;
        const line = readLine(io, &buf) catch "";
        if (line.len > 0) parsePortList(cfg, line) catch {};
    }
    cfg.litenet_filter = try promptYesNo(io, stdout, "LiteNetLib payload filter?", true);

    if (cfg.no_file and !cfg.stdout and !cfg.http) {
        cfg.no_file = false;
        cfg.log_dir = try allocator.dupe(u8, "./replays");
    }

    var cmd_buf: [1024]u8 = undefined;
    const cmd = buildLaunchCommand(cfg, &cmd_buf) catch "(cmd too long)";
    try stdout.print("\n--- Next time ---\n{s}\n----------------\n", .{cmd});
    try stdout.flush();
    if (try promptYesNo(io, stdout, "Write ./ln-capture.sh?", true)) {
        writeLaunchScript(io, cfg) catch {};
        try stdout.writeAll("Wrote ./ln-capture.sh\n");
        try stdout.flush();
    }
    try stdout.writeAll("\nStart/enter the game. Watch [discover] logs.\n\n");
    try stdout.flush();
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    var cfg = parseArgs(allocator, args) catch |err| {
        std.log.err("Argument error: {s}. Try --help.", .{@errorName(err)});
        return err;
    };

    if (cfg.help) {
        var stdout_buf: [2048]u8 = undefined;
        var stdout_writer = Io.File.stdout().writer(io, &stdout_buf);
        try printHelp(&stdout_writer.interface);
        try stdout_writer.interface.flush();
        return;
    }

    const interfaces = try listInterfaces(io, allocator);
    defer freeInterfaces(allocator, interfaces);
    if (interfaces.len == 0) return error.NoInterfaces;

    if (cfg.interface == null) {
        if (cfg.force_yes) {
            std.log.err("--interface is required with --yes", .{});
            return error.MissingInterface;
        }
        try runWizard(io, allocator, &cfg, interfaces);
    }

    const ifname = cfg.interface orelse {
        std.log.err("No interface selected", .{});
        return error.MissingInterface;
    };

    port_filter.io = io;
    port_filter.auto_enabled = cfg.auto_ports;
    port_filter.process_name = cfg.process_name;
    port_filter.litenet = cfg.litenet_filter;
    port_filter.all_udp = cfg.all_udp;
    port_filter.verbose_once = true;
    if (cfg.ports_len > 0) port_filter.setManual(cfg.ports[0..cfg.ports_len]);
    if (cfg.auto_ports) {
        port_filter.refreshAuto();
    }
    if (cfg.litenet_filter) std.log.info("LiteNetLib payload filter: ON", .{});
    if (cfg.all_udp) std.log.warn("ALL-UDP mode enabled", .{});

    hub.allocator = allocator;
    hub.io = io;
    if (cfg.stdout) hub.enableStdout(io);

    if (!cfg.no_file) {
        try hub.openFile(io, cfg.log_dir, cfg.log_file);
        std.log.info("Recording → {s}", .{hub.path()});
    } else if (hub.start_ns == 0) {
        hub.start_ns = monoNowNs();
    }

    if (cfg.sessions_dir == null and cfg.log_dir != null) cfg.sessions_dir = cfg.log_dir;

    if (cfg.http) {
        const ctx = HttpCtx{
            .io = io,
            .allocator = allocator,
            .static_dir = cfg.static_dir,
            .sessions_dir = cfg.sessions_dir,
            .port = cfg.http_port,
            .bind = cfg.http_bind,
        };
        const t = try std.Thread.spawn(.{}, httpServerThread, .{ctx});
        t.detach();
        if (cfg.open_browser) {
            var url_buf: [128]u8 = undefined;
            const url = std.fmt.bufPrint(&url_buf, "http://{s}:{d}/", .{ cfg.http_bind, cfg.http_port }) catch "http://127.0.0.1:8765/";
            tryOpenBrowser(io, url);
        }
    }

    const sock_rc = linux.socket(AF_PACKET, SOCK_RAW, std.mem.nativeToBig(u32, ETH_P_ALL));
    try check(sock_rc, "socket");
    const sock: i32 = @intCast(sock_rc);
    defer _ = linux.close(sock);

    var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
    ifr.ifrn.name[ifname.len] = 0;
    try check(linux.ioctl(sock, linux.SIOCGIFINDEX, @intFromPtr(&ifr)), "ioctl");
    const ifindex = ifr.ifru.ivalue;
    if (ifindex <= 0) {
        std.log.err("Interface '{s}' not found", .{ifname});
        return error.BadInterface;
    }
    std.log.info("Bound to '{s}' (ifindex={d})", .{ ifname, ifindex });

    var mreq = packet_mreq{ .mr_ifindex = ifindex, .mr_type = PACKET_MR_PROMISC };
    _ = linux.setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, std.mem.asBytes(&mreq), @sizeOf(packet_mreq));

    var addr = sockaddr_ll{ .protocol = std.mem.nativeToBig(u16, ETH_P_ALL), .ifindex = ifindex };
    try check(linux.bind(sock, @ptrCast(&addr), @sizeOf(sockaddr_ll)), "bind");

    std.log.info("Capture on {s} — status every 5s, [discover] on each port scan", .{ifname});
    defer hub.close();
    stats.last_status_ns = monoNowNs();

    var pkt_buf: [65535]u8 = undefined;
    while (true) {
        stats.maybeReport(&cfg);

        var sll: sockaddr_ll = undefined;
        var addr_len: u32 = @sizeOf(sockaddr_ll);
        const len_rc = linux.recvfrom(sock, &pkt_buf, pkt_buf.len, 0, @ptrCast(&sll), &addr_len);
        switch (linux.errno(len_rc)) {
            .SUCCESS => {
                const len: usize = @intCast(len_rc);
                stats.frames_total += 1;
                if (len < 34) continue;
                if (std.mem.readInt(u16, pkt_buf[12..14], .big) != ETH_P_IP) {
                    stats.frames_non_ip += 1;
                    continue;
                }
                const ip = pkt_buf[14..];
                const ihl: usize = @as(usize, ip[0] & 0x0f) * 4;
                if (ip[9] != IPPROTO_UDP or len < 14 + ihl + 8) {
                    stats.frames_non_udp += 1;
                    continue;
                }
                const udp = ip[ihl..];
                const sport = std.mem.readInt(u16, udp[0..2], .big);
                const dport = std.mem.readInt(u16, udp[2..4], .big);
                const ulen = std.mem.readInt(u16, udp[4..6], .big);
                if (ulen < 8) continue;
                const poff = 14 + ihl + 8;
                const plen = @min(ulen - 8, len - poff);
                if (plen == 0) continue;
                const payload = pkt_buf[poff..][0..plen];

                stats.udp_seen += 1;
                if (!stats.first_udp_logged) {
                    stats.first_udp_logged = true;
                    std.log.info("First UDP on wire: sport={d} dport={d} len={d}", .{ sport, dport, plen });
                }

                switch (port_filter.acceptWithReason(sport, dport, payload)) {
                    0 => {
                        if (!stats.first_accept_logged) {
                            stats.first_accept_logged = true;
                            std.log.info("First ACCEPTED packet: sport={d} dport={d} len={d}", .{ sport, dport, plen });
                        }
                        hub.record(directionFromPkttype(sll.pkttype), payload);
                    },
                    1 => stats.rejected_no_ports += 1,
                    2 => stats.rejected_port += 1,
                    3 => stats.rejected_litenet += 1,
                    else => {},
                }
            },
            .INTR => continue,
            else => |e| {
                std.log.warn("recvfrom: {s}", .{@tagName(e)});
                break;
            },
        }
    }
}
