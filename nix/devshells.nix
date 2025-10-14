{ pkgs, system, common_packages, openssl_1_0_2, openssl_1_1_1, openssl_3_0
, aws-lc, aws-lc-fips-2022, aws-lc-fips-2024, writeScript }:

let
    commonShellHook = ''
      export CC="$(command -v clang)"
      export CXX="$(command -v clang++)"
      export AR="$(command -v llvm-ar || command -v ar)"
      if command -v ninja >/dev/null 2>&1; then
        export CMAKE_GENERATOR="Ninja"
      fi

      export LIBCLANG_PATH="${pkgs.lib.getLib pkgs.llvmPackages_18.libclang}/lib"
      export CLANG_PATH="${pkgs.llvmPackages_18.clang}/bin/clang"
      if [ -n "$LD_LIBRARY_PATH" ]; then
        export LD_LIBRARY_PATH="$LIBCLANG_PATH:$LD_LIBRARY_PATH"
      else
        export LD_LIBRARY_PATH="$LIBCLANG_PATH"
      fi

      export BINDGEN_EXTRA_CLANG_ARGS="$(
        cat ${pkgs.stdenv.cc}/nix-support/libc-crt1-cflags
      ) $(
        cat ${pkgs.stdenv.cc}/nix-support/libc-cflags
      ) $(
        cat ${pkgs.stdenv.cc}/nix-support/cc-cflags
      ) $(
      cat ${pkgs.stdenv.cc}/nix-support/libcxx-cxxflags
    ) $(
      # For clang toolchain: add builtin headers after system ones
        if ${pkgs.lib.boolToString pkgs.stdenv.cc.isClang}; then
        echo -idirafter ${pkgs.stdenv.cc.cc}/lib/clang/$(${pkgs.coreutils}/bin/basename ${pkgs.stdenv.cc.cc}/lib/clang/* | head -n1)/include
        fi
      ) $(
        # For GCC toolchain: add libstdc++ and fixed includes + GCC private includes
      if ${pkgs.lib.boolToString pkgs.stdenv.cc.isGNU}; then
        echo -isystem ${pkgs.stdenv.cc.cc}/include/c++/$(${pkgs.lib.getVersion pkgs.stdenv.cc.cc}) \
              -isystem ${pkgs.stdenv.cc.cc}/include/c++/$(${pkgs.lib.getVersion pkgs.stdenv.cc.cc})/${pkgs.stdenv.hostPlatform.config} \
            -idirafter ${pkgs.stdenv.cc.cc}/lib/gcc/${pkgs.stdenv.hostPlatform.config}/$(${pkgs.lib.getVersion pkgs.stdenv.cc.cc})/include
      fi
  )"
  '';

  commonToolInputs = [
    pkgs.llvmPackages_18.clang
    pkgs.llvmPackages_18.lld
    pkgs.cmake
    pkgs.ninja
    pkgs.pkg-config
    pkgs.rustc
    pkgs.cargo
    pkgs.rustfmt
  ];

  awsLcStatic = aws-lc.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DBUILD_SHARED_LIBS=OFF"
      "-DBUILD_TESTING=OFF"
    ];
  });
  
  awsLcFips2024Static = aws-lc-fips-2024.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or []) ++ [
      "-DBUILD_SHARED_LIBS=OFF"
      "-DBUILD_TESTING=OFF"
    ];
  });

  # Define the default devShell
  default = pkgs.mkShell {
    inherit system;
    # keep minimal buildInputs; most tools come via `packages = common_packages`
    buildInputs = commonToolInputs ++ [ pkgs.cmake openssl_3_0 ];
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
    buildInputs = commonToolInputs ++ [ pkgs.cmake openssl_1_1_1 ];
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
    buildInputs = commonToolInputs ++ [ pkgs.cmake pkgs.libressl ];
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
    buildInputs = commonToolInputs ++ [ pkgs.cmake openssl_1_0_2 ];
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
  awslc_shell = default.overrideAttrs (final: prev: {
    buildInputs = commonToolInputs ++ [ pkgs.cmake awsLcStatic ];
    S2N_LIBCRYPTO = "awslc";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      # Prefer aws-lc’s dev+lib outputs so CMake sees static targets
      export CMAKE_PREFIX_PATH="${awsLcStatic}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
      ${commonShellHook}
      source ${writeScript ./shell.sh}
    '';
  });

  awslcfips2022_shell = default.overrideAttrs (finalAttrs: previousAttrs: {
    buildInputs = commonToolInputs ++ [ pkgs.cmake aws-lc-fips-2022 ];
    S2N_LIBCRYPTO = "awslc-fips-2022";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"

      ${commonShellHook}

      source ${writeScript ./shell.sh}
    '';
  });

  awslcfips2024_shell = default.overrideAttrs (final: prev: {
    buildInputs = commonToolInputs ++ [ pkgs.cmake awsLcFips2024Static ];
    S2N_LIBCRYPTO = "awslc-fips-2024";
    shellHook = ''
      echo Setting up $S2N_LIBCRYPTO environment from flake.nix...
      export PATH=${openssl_1_1_1}/bin:$PATH
      export PS1="[nix $S2N_LIBCRYPTO] $PS1"
      export CMAKE_PREFIX_PATH="${awsLcFips2024Static}''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
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