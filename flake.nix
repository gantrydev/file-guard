{
  description = "file-guard - per-process credential access control (macOS Endpoint Security / Linux FUSE)";

  # Single input on purpose: a credential-guarding tool should keep its own
  # supply chain minimal.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      # Linux only. The macOS (Endpoint Security) backend is not built - see
      # README "macOS".
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: lib.genAttrs systems (system: f system (import nixpkgs { inherit system; }));
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
    in
    {
      # ── Package (Linux) ───────────────────────────────────────────────────
      # macOS needs the EndpointSecurity entitlement + a signed binary + root,
      # which can't be produced in the Nix sandbox - build it manually there
      # (see README). The flake ships the Linux/FUSE build.
      packages = forAllSystems (system: pkgs:
        lib.optionalAttrs pkgs.stdenv.isLinux (
          let
            file-guard = pkgs.rustPlatform.buildRustPackage {
              pname = "file-guard";
              inherit version;
              src = lib.cleanSource ./.;
              cargoLock.lockFile = ./Cargo.lock;
              nativeBuildInputs = [ pkgs.pkg-config ];
              buildInputs = [ pkgs.fuse3 ];
              meta = {
                description = "Per-process credential file access control (FUSE)";
                homepage = "https://github.com/gantryops/file-guard";
                license = lib.licenses.mit;
                mainProgram = "file-guard";
                platforms = lib.platforms.linux;
              };
            };
          in
          {
            inherit file-guard;
            default = file-guard;
          }
        )
      );

      # ── Dev shell (all systems) ───────────────────────────────────────────
      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.fuse3 ];
          packages = with pkgs; [ cargo rustc clippy rustfmt rust-analyzer ];
        };
      });

      formatter = forAllSystems (_system: pkgs: pkgs.nixpkgs-fmt);

      # ── NixOS module: privileged daemon + session prompt agent ────────────
      # Runs file-guard as root so the backing store is owned by root (not the
      # guarded user) - this is what makes the tool resist same-uid malware on
      # Linux. Validate on your host before relying on it.
      #
      # Prompts are rendered by a separate session agent. Its listening socket is
      # created by the ROOT systemd socket unit inside a root-owned directory and
      # handed to the agent via socket activation - so same-uid malware can
      # neither hijack the socket name nor connect to it (0600 root). The agent
      # itself runs as the guarded user (for GUI access); set `agentEnvironment`
      # so GUI dialogs reach that user's display.
      nixosModules.default = { config, pkgs, ... }:
        let
          inherit (lib) mkEnableOption mkOption mkIf types mapAttrsToList;
          cfg = config.services.file-guard;
          socketPath = "/run/file-guard/agent.sock";
        in
        {
          options.services.file-guard = {
            enable = mkEnableOption "file-guard credential access-control daemon";

            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = "file-guard from this flake";
              description = "The file-guard package to run.";
            };

            user = mkOption {
              type = types.str;
              example = "alice";
              description = ''
                The user whose credentials are guarded. `~` in watched paths
                resolves to this user's home (the daemon itself runs as root).
                The prompt agent runs as this user.
              '';
            };

            uid = mkOption {
              type = types.int;
              default = 1000;
              description = ''
                Numeric uid of the guarded user. Used to locate their session
                bus and runtime dir (`/run/user/<uid>`) so GUI prompts reach
                their display. The default suits a typical single-user desktop.
              '';
            };

            configFile = mkOption {
              type = types.path;
              example = "/etc/file-guard/config.toml";
              description = "Path to the file-guard config.toml the daemon reads.";
            };

            promptMethod = mkOption {
              type = types.enum [ "terminal" "gui" "notification" ];
              default = "gui";
              description = ''
                How the session agent renders prompts. `gui` works out of the
                box on a single-user graphical session (zenity is bundled via
                `guiPackages` and the session env is filled from `uid`). If no
                display is reachable it falls back and unknown accesses deny on
                timeout, so `default_action = "deny"` stays safe headless.
              '';
            };

            guiPackages = mkOption {
              type = types.listOf types.package;
              default = [ pkgs.zenity pkgs.libnotify ];
              defaultText = "[ pkgs.zenity pkgs.libnotify ]";
              description = ''
                Packages placed on the prompt agent's PATH so GUI dialogs and
                desktop notifications work without manual setup. `zenity`
                renders the dialog; `libnotify` provides `notify-send`. KDE
                users can add `pkgs.kdePackages.kdialog`.
              '';
            };

            agentEnvironment = mkOption {
              type = types.attrsOf types.str;
              default = {
                DISPLAY = ":0";
                WAYLAND_DISPLAY = "wayland-1";
                XDG_RUNTIME_DIR = "/run/user/${toString cfg.uid}";
                DBUS_SESSION_BUS_ADDRESS = "unix:path=/run/user/${toString cfg.uid}/bus";
              };
              defaultText = ''sensible single-user desktop defaults derived from `uid`'';
              example = {
                DISPLAY = ":1";
                XAUTHORITY = "/home/alice/.Xauthority";
              };
              description = ''
                Environment for the prompt agent so GUI dialogs/notifications
                reach the guarded user's graphical session. The default targets
                a single-user Wayland/X session; override for a non-standard
                display, multi-seat, or pure-X11 setup needing `XAUTHORITY`.
              '';
            };
          };

          config = mkIf cfg.enable {
            # Let the guarded user's processes reach the root-owned FUSE mount.
            programs.fuse.userAllowOther = true;

            # Root-owned rendezvous directory: the socket name can't be created
            # or hijacked by the guarded (non-root) user.
            systemd.tmpfiles.rules = [ "d /run/file-guard 0755 root root -" ];

            # The listening socket, created and held by root (PID 1) - the trust
            # anchor. 0600 means only root (the daemon) may connect.
            systemd.sockets.file-guard-agent = {
              description = "file-guard prompt agent socket";
              wantedBy = [ "sockets.target" ];
              socketConfig = {
                ListenStream = socketPath;
                SocketMode = "0600";
              };
            };

            # Socket-activated agent, running as the guarded user so GUI/notifs
            # reach their session. Receives the listening fd via LISTEN_FDS.
            systemd.services.file-guard-agent = {
              description = "file-guard prompt agent";
              requires = [ "file-guard-agent.socket" ];
              after = [ "file-guard-agent.socket" ];
              # zenity / notify-send on PATH so GUI prompts work out of the box.
              path = cfg.guiPackages;
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/file-guard agent --method ${cfg.promptMethod}";
                User = cfg.user;
                Environment = mapAttrsToList (k: v: "${k}=${v}") cfg.agentEnvironment;
              };
            };

            systemd.services.file-guard = {
              description = "file-guard credential access control";
              wantedBy = [ "multi-user.target" ];
              after = [ "local-fs.target" "file-guard-agent.socket" ];
              wants = [ "file-guard-agent.socket" ];

              # Mounts created by the service must be visible to the whole host,
              # so do NOT enable mount-namespacing sandbox options (ProtectHome,
              # PrivateMounts, …) - they would hide the FUSE mounts or /home.
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/file-guard start";
                Restart = "on-failure";
                RestartSec = 2;
                # `start` runs in the foreground and handles SIGTERM by unmounting.
                Type = "exec";
                KillSignal = "SIGTERM";
                TimeoutStopSec = 15;
                # root:root 0700 store, unreadable by the guarded user.
                # The daemon PID file lives in /run/file-guard (created by the
                # tmpfiles rule above), the audit log under StateDirectory.
                StateDirectory = "file-guard";
                StateDirectoryMode = "0700";
                Environment = [
                  "FILE_GUARD_USER=${cfg.user}"
                  "FILE_GUARD_CONFIG=${cfg.configFile}"
                  "FILE_GUARD_STORE_DIR=/var/lib/file-guard/store"
                  "FILE_GUARD_AGENT_SOCKET=${socketPath}"
                ];
              };
            };
          };
        };
    };
}
