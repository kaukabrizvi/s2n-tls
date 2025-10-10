{ pkgs, system, common_packages, openssl_1_0_2, openssl_1_1_1, openssl_3_0
, aws-lc, aws-lc-fips-2022, aws-lc-fips-2024, writeScript }:

let
  # Shared shellHook to force Nix toolchain paths for CMake discovery
  commonShellHook = ''
    # Prefer Nix-provided Clang/LLVM tools (avoid /usr/bin)
    export CC="$(command -v clang)"
    export CXX="$(command -v clang++)"
    export AR="$(command -v llvm-ar || command -v ar)"
    export NM="$(command -v llvm-nm || command -v nm)"
    export RANLIB="$(command -v llvm-ranlib || command -v ranlib)"
    export OBJCOPY="$(command -v llvm-objcopy || command -v objcopy)"

    # Optional: prefer Ninja if present (faster/more deterministic)
    if command -v ninja >/dev/null 2>&1; then
      export CMAKE_GENERATOR="Ninja"
    fi

    echo "Toolchain:"
    echo "  CC=$CC"
    echo "  CXX=$CXX"
    echo "  AR=$AR"
    echo "  NM=$NM"
    echo "  RANLIB=$RANLIB"
    echo "  OBJCOPY=$OBJCOPY"
  '';

  # Define the default devShell
  default = pkgs.mkShell {
    inherit system;
    # keep minimal buildInputs; most tools come via `packages = common_packages`
    buildInputs = [ pkgs.cmake openssl_3_0 ];
    packages = common_packages;

    S2N_LIBCRYPTO = "openssl-3.0";
    OPENSSL_1_0_2_INSTALL_DIR =
      if openssl_1_0_2 != null then "${openssl_1_0_2}" else "";
    OPENSSL_1_1_1_INSTALL_DIR = "${openssl_1_1_1}";
    OPENSSL_3_0_INSTALL_DIR   = "${openssl_3_0}";
    AWSLC_INSTALL_DIR         = "${aws-lc}";
    AWSLC_FIPS_2022_INSTALL_DIR = "${aws-lc-fips-2022}";
    AWSLC_FIPS_2024_INSTALL_DIR = "${aws-lc-fips-2024}";
    GNUTLS_INSTALL_DIR        = "${pkgs.gnutls}";
    LIBRESSL_INSTALL_DIR      = "${pkgs.libressl}";

    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      # Integ s_client/server tests expect openssl 1.1.1 on PATH
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      # project shell script
      source ${writeScript ./shell.sh}
    '';
  };

  # Define the openssl111 devShell
  openssl111 = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake openssl_1_1_1 ];
    S2N_LIBCRYPTO = "openssl-1.1.1";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

  # Define the libressl devShell
  libressl_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake pkgs.libressl ];
    S2N_LIBCRYPTO = "libressl";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

  openssl102 = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake openssl_1_0_2 ];
    S2N_LIBCRYPTO = "openssl-1.0.2";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

  # Define the awslc devShell
  awslc_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake aws-lc ];
    S2N_LIBCRYPTO = "awslc";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

  awslcfips2022_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake aws-lc-fips-2022 ];
    S2N_LIBCRYPTO = "awslc-fips-2022";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

  awslcfips2024_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = [ pkgs.cmake aws-lc-fips-2024 ];
    S2N_LIBCRYPTO = "awslc-fips-2024";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

in {
  default = default;
  openssl111 = openssl111;
  libressl = libressl_shell;
  openssl102 = openssl102;
  awslc = awslc_shell;
  awslcfips2022 = awslcfips2022_shell;
  awslcfips2024 = awslcfips2024_shell;
}
