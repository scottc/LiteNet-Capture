# LiteNet Capture

Capture & expose LiteNet ((Website)[https://revenantx.github.io/LiteNetLib/index.html], (Source)[https://github.com/RevenantX/LiteNetLib]) game data network traffic for analysis. ie Spirit Vale ([steam](https://store.steampowered.com/app/3767850/SpiritVale/)) by [Baikun Interactive](https://impress.games/press-kit/baikun-interactive/spiritvale), is one such game. This allows users to build things like DPS meters for ARPG & MMORPG games. Or custom dashboards with live or recorded game data information.

This let's you replay and analyze slices of game data... Let's say you're interested in battle metrics for a dungeon runs & boss fights... this could be a great tool for that purpose.

And perhaps other uses for other genre of games.

## Security Disclaimer!

This app does not come with any warrenty or security guarentees of any kind! And we are not responsable for any damages that may occur as a result. ie, your account getting banned from the game service, loss of data, your bank account getting hacked, cosmic space rays making your pet cat speaking human language or any other forms of loss or damages!

**USE AT YOUR OWN RISK!**

And in good faith, we should explain the risk profile and attack surface for this application, before you should decide to use it or not!

First of all, you need to understand what the application actually does. Here is a summary of what it does, why it's nessisary, and for what purpose.

1) Check the game's running process for which UDP ports it's using. This is because LiteNet uses dynamically allocated UDP ports, so to not accidentally capture any unrelated network traffic. ie some banking app, or private chat app's network traffic: `[discover] auto UDP ports: 51212,34853,35513,52077,36140,53072,37156,53856,54911,54983,38627,55755,39672,56635,56748,57306,41062,57496,58610,59496
`
2) Filter the packets if they are actually indeed look like LiteNet packets. Once again, to prevent accidentally capturing unrelated traffic.
```zig
fn looksLikeLiteNet(payload: []const u8) bool {
    if (payload.len == 0) return false;
    return (payload[0] & 0x1f) <= LITENET_PROP_MAX;
}
```
3) Capturing isn't enough to be useful by itself, so we need a way for the user to actually use the captured information. For this purpose, we can stream the data to: `stdout`, file system disk or to an intergrated mini webserver & websocket for custom user specified dashboards.

For this to actually happen, the application needs root privilages to inspect user space proccesses & capture raw network traffic, because we can capture traffic of other user space processes, ie the game data. But this could also be a banking app or any other number of things. So there is elevated root/administator level privileges. Always check if the vendor & source code is secure and can be trusted, when providing elevated privliages!

But we also have the mini http web server feature, so it's possible for let's say your web browser, or any other application to connect to this application! And this application then needs to handle inputs and outputs via HTTP & websockets. So there is an attack surface. And I'm strongly considering removing this feature entirely.

For the HTTP HTML, UI to be useful... it needs JavaScript to actually function... to consume the websocket data and to present it to the user. Why is this a problem? Well the nodejs, JavaScript & web ecosystem... is quite notorious for things like XSS, and supply chain attacks with npm package dependencies. So if you were to download and use someone elses dashboard, which has some npm dependencies that havn't been throughly audited & closely monitored. You could be at risk of accidentially downloading some malicious JavaScript, that's either generically malicious or targetedly malicious.

This application is vibe coded & written in the low level language, zig! So there are even more possibilities for "memory safety" vulenerabilities. If in doubt, you can use the FIL-C LLVM compiler for memory safety.

And the combination of vibe coded, low level, elevated privliages, http/ws/other attack surface & the potental for naively evaluated JavaScript, is IMHO. A very scary & risky proposition.

(Note: Opinions are my own personal beliefs, and should not be taken as a statement of objectively true fact. Please do your own research & verify any factual information!)

And for now, that's the current implementation & design.

If in doubt, consult a cyber security expert & get a second opinion.

And it's possible to download, fork and modify the source code. We are not responsible for any forks, or changes beyond this repo or for what they decide to do with the source code.

**Once again, USE AT YOUR OWN RISK! YOU HAVE BEEN WARNED!**

## Runtime Requirements

- A standard linux system.

I use linux, so I develop for my system, and don't have the time, effort or desire to develop, test and support for other operating systems. I have no desire to do so, except for maybe something like a new microkernal OS should I decide to switch operating systems.

## Build Requirements

- Zig compiler - version `0.16.0` (at the time of writing)

I also pin the exact version to the nix flake, should you want a reproduceable development environment.

## Building from source

This application uses the zig build system:

```sh
nix develop # [Optional] get a reproduceable dev environment with exact pinned zig version.
zig build # just do an unoptimized debug build, produces ./zig-out/bin/litenet_capture
sudo zig run ./src/main.zig # build & run the unoptimised debug build
# Note: sudo is used here, because the app needs elevated privliages to fully function, not the compiler.
```

That's it.

If you need more help, refer to zig's build system documentation, you may want to do an optimised LLVM build for more faster performance.

## First Run - Setup Wizard

```sh
zig run ./src/main.zig
```

### Output

```sh
=== LiteNet capture — setup wizard ===

Available network interfaces:

  [1] enp0s31f6
  [2] lo
  [3] wlp4s0
  [4] wwan0

Enter number (1-4) or interface name: 3
Selected: wlp4s0

Write replay file to disk? [Y/n]:
Directory [./replays]:
Stream JSONL to stdout? [y/N]:
Start HTTP + WebSocket server? [Y/n]:
Open browser? [Y/n]:
Auto-discover game UDP ports? [Y/n]:
Process name substring [SpiritVale]:
Optional fixed ports (comma-separated, empty skip):
LiteNetLib payload filter? [Y/n]:

--- Next time ---
sudo zig run src/main.zig -- -i wlp4s0 -d ./replays --sessions-dir ./replays -w --open
----------------
Write ./ln-capture.sh? [Y/n]:
Wrote ./ln-capture.sh

Start/enter the game. Watch [discover] logs.

info: [discover] scanning /proc for process name containing 'SpiritVale'…
info: [discover] scan done: pids=321 spirit-named-comm=0 matches='SpiritVale'=0 socket-inodes=0
info: LiteNetLib payload filter: ON
info: Recording → ./replays/sv-20260820T055721Z.sv.replay.jsonl
info: HTTP server on http://127.0.0.1:8765/  (WS: ws://127.0.0.1:8765/ws)
```

## Screenshots

TODO: Upload screenshot. If you've found this project you've probably seen some screenshots already.

## Inspriation

Credit goes to [Spirit Vale Overlay](https://github.com/kar-mi/spirit-vale-overlay) project.

Basically I wanted to try use Spirit Vale Overlay, but it uses npcap for network capture... And I'm using linux. Sure there is wireshark project and some related wireshark `.so`, `.dll` shared objects (dynamically linked libraries)... that could be used instead.

But instead I opt to basically re-create the project, including the the low level packet capture, reporting & UI features. For my system, my personal use, and also as an educational hobby to learn more about the more advanced operating system features & how to use them.

Long story short, to replace npcap for capturing Spirit Vale... which under the hood uses LiteNet for it's network protocol.

So this is effectively a generic LiteNet packet capturing app, to work with Spirit Vale Overlay. We could go more generic, or more specific... but let's just stop here.

But I also ended up writing my own UI for it too, instead of figuring out how to intergrate it, and that's how I ended up with this project.

Since alot of the work is based off Spirit Vale Overlay design and game event decoders, I'll release this with the same APGLv3 license, with the same spirit and intention. Please respect the licencing terms!

## Legal - Copyright, Trademarks & Intellectual Property

This project is in no way affiliated with Spirit Vale, Baikun Interactive, LiteNet, Unity game engine, Spirit Vale Overlay, NPM, Nodejs, Zig, Nix or Linux.

All copyright & IP belong to their respective owners.

Opinions are my own personal beliefs, and should not be taken as a statement of objectively true fact. Please do your own research & verify any factual information!

If you have any concerns, feel free to contact me, unsure how active and responsive, from wherever you happened to source this code from.

I'm open to the idea of changing the license, terms or avaliablity of this project. I'm not overly attached to it! But some positive recognition or a job offer could be nice! DMCA takedowns, legal threats or letters from lawyers... would be less then pleasant, so please don't. Choose to be kind & civil instead.
