cmake_minimum_required(VERSION 3.16)
project(btc_signer_gui VERSION 1.0.0 LANGUAGES C CXX)

#
# SignerOS kiosk build.
#
# Two shapes come out of this file:
#
#   SIGNEROS_BUILD_GUI=ON  (default, what Buildroot builds)
#       btc_signer_gui  - the Qt kiosk, which also implements --self-test
#       signeros-ramwipe
#
#   SIGNEROS_BUILD_GUI=OFF
#       btc_signer_gui  - the same binary minus the Qt user interface, so the
#                         signing core can be compiled and exercised on a build
#                         machine with no Qt installed. Used by
#                         scripts/host_selftest.sh.
#
# The signing core (src/core) never includes a Qt header. That separation is
# deliberate: everything that touches key material or parses attacker-controlled
# files is testable without a display.
#

# The SignerOS release version, which the binary reports and the kiosk shows.
#
# Buildroot passes it in from VERSION at the repo root (see the package makefile
# and scripts/build.sh); a standalone build - scripts/host_selftest.sh, or an
# IDE pointed at this directory - reads the same file two levels up. A build
# from a source tree copied away from the repo has neither, and gets a string
# that is obviously not a release rather than a plausible wrong number.
set(SIGNEROS_VERSION "" CACHE STRING "SignerOS release version")
if(NOT SIGNEROS_VERSION AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION")
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION" SIGNEROS_VERSION)
    string(STRIP "${SIGNEROS_VERSION}" SIGNEROS_VERSION)
endif()
if(NOT SIGNEROS_VERSION)
    set(SIGNEROS_VERSION "0.0.0-dev")
endif()
message(STATUS "SignerOS version: ${SIGNEROS_VERSION}")

set(SIGNEROS_QT_MAJOR "5" CACHE STRING "Qt major version to build against (5 or 6)")
set(SIGNEROS_NETWORK "mainnet" CACHE STRING "Compiled-in default Bitcoin network")
option(SIGNEROS_WORD_SUGGESTIONS "Show BIP39 word suggestions while typing" ON)
option(SIGNEROS_BUILD_GUI "Build the Qt user interface" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    # Small footprint by default: the rootfs is a RAM-resident initramfs, so
    # binary size is permanently occupied physical memory.
    set(CMAKE_BUILD_TYPE MinSizeRel CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# libwally-core
#
# Located via pkg-config when available, then pinned to the static archive: the
# signing code must be inside our binary, not in a swappable shared object.
# board/signeros/post-build.sh independently asserts that the installed binary
# has no libwallycore in its DT_NEEDED list.
# ---------------------------------------------------------------------------
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PC_WALLY QUIET wallycore)
endif()

find_path(WALLY_INCLUDE_DIR
    NAMES wally_psbt.h
    HINTS ${PC_WALLY_INCLUDEDIR} ${PC_WALLY_INCLUDE_DIRS}
    PATH_SUFFIXES wally libwally-core
)
find_library(WALLY_LIBRARY
    NAMES libwallycore.a wallycore
    HINTS ${PC_WALLY_LIBDIR} ${PC_WALLY_LIBRARY_DIRS}
)
# libwally bundles secp256k1-zkp. Depending on the build it is either folded
# into libwallycore.a or installed alongside it.
find_library(WALLY_SECP_LIBRARY
    NAMES libsecp256k1.a secp256k1
    HINTS ${PC_WALLY_LIBDIR} ${PC_WALLY_LIBRARY_DIRS}
)

if(NOT WALLY_INCLUDE_DIR OR NOT WALLY_LIBRARY)
    message(FATAL_ERROR
        "libwally-core not found.\n"
        "  include dir: ${WALLY_INCLUDE_DIR}\n"
        "  library    : ${WALLY_LIBRARY}\n"
        "Install it (Buildroot: BR2_PACKAGE_LIBWALLY_CORE=y) or point CMake at it "
        "with -DCMAKE_PREFIX_PATH=<prefix>.")
endif()

message(STATUS "libwally-core: ${WALLY_LIBRARY}")
message(STATUS "libwally headers: ${WALLY_INCLUDE_DIR}")

# ---------------------------------------------------------------------------
# Hardening flags
#
# Buildroot already injects most of these through BR2_SSP_STRONG /
# BR2_RELRO_FULL / BR2_FORTIFY_SOURCE_2; repeating them here means a standalone
# host build gets the same treatment, and duplicates are harmless.
#
# -fno-builtin-memset matters specifically: it is what stops the compiler
# turning the memset inside secureWipe() into nothing at -Os.
# ---------------------------------------------------------------------------
add_compile_options(
    -Wall -Wextra
    -fstack-protector-strong
    -fno-builtin-memset
    -fno-strict-aliasing
)
add_link_options(
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)
if(NOT CMAKE_CXX_FLAGS MATCHES "_FORTIFY_SOURCE")
    add_compile_definitions($<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)
endif()

# ---------------------------------------------------------------------------
# Signing core: no Qt, no display, no globals beyond the single key slot.
# ---------------------------------------------------------------------------
add_library(signer_core STATIC
    src/core/secure_memory.cpp
    src/core/psbt_engine.cpp
    src/core/entropy.cpp
    src/core/wallet_export.cpp
    src/core/selftest.cpp
)
target_include_directories(signer_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${WALLY_INCLUDE_DIR}
)
target_link_libraries(signer_core PUBLIC ${WALLY_LIBRARY})
if(WALLY_SECP_LIBRARY)
    target_link_libraries(signer_core PUBLIC ${WALLY_SECP_LIBRARY})
endif()
target_compile_definitions(signer_core PUBLIC
    SIGNEROS_DEFAULT_NETWORK="${SIGNEROS_NETWORK}"
    SIGNEROS_VERSION_STR="${SIGNEROS_VERSION}"
)

# ---------------------------------------------------------------------------
# The kiosk
# ---------------------------------------------------------------------------
set(SIGNER_SOURCES src/main.cpp)

if(SIGNEROS_BUILD_GUI)
    set(CMAKE_AUTOMOC ON)
    find_package(Qt${SIGNEROS_QT_MAJOR} REQUIRED COMPONENTS Core Gui Widgets)
    message(STATUS "Qt: ${Qt${SIGNEROS_QT_MAJOR}Core_VERSION}")

    list(APPEND SIGNER_SOURCES
        src/ui/theme.cpp
        src/ui/osk.cpp
        src/ui/osk_panel.cpp
        src/ui/save_as.cpp
        src/ui/secret_buffers.cpp
        src/ui/seed_view.cpp
        src/ui/app_window.cpp
        src/ui/screen_splash.cpp
        src/ui/screen_home.cpp
        src/ui/screen_scan.cpp
        src/ui/screen_inspect.cpp
        src/ui/screen_sign.cpp
        src/ui/screen_create.cpp
        src/ui/screen_import.cpp
        src/ui/screen_shutdown.cpp
    )

    # -----------------------------------------------------------------------
    # Touchpad support.
    #
    # src/ui/touchpad.cpp feeds QWindowSystemInterface, which lives in Qt's QPA
    # headers - shipped by a normal Qt install but formally private, so the
    # GuiPrivate target is what carries their include path. Detected rather than
    # required: this is one input device's worth of behaviour, and a Qt build
    # with the private headers stripped should still produce a working signer
    # rather than failing an hour into a Buildroot run. main.cpp falls back to
    # the old classification when SIGNEROS_TOUCHPAD is not defined.
    #
    # The header is looked for explicitly instead of trusting the target to
    # exist, because a target whose include directory was stripped fails at
    # compile time - which on this project means failing late and expensively.
    # -----------------------------------------------------------------------
    set(_qt_gui_private Qt${SIGNEROS_QT_MAJOR}::GuiPrivate)
    if(TARGET ${_qt_gui_private})
        get_target_property(_qpa_includes ${_qt_gui_private} INTERFACE_INCLUDE_DIRECTORIES)
        find_path(SIGNEROS_QPA_INCLUDE_DIR
            NAMES qpa/qwindowsysteminterface.h
            HINTS ${_qpa_includes}
            NO_DEFAULT_PATH
        )
    endif()

    if(SIGNEROS_QPA_INCLUDE_DIR)
        message(STATUS "Touchpad support: yes (QPA headers in ${SIGNEROS_QPA_INCLUDE_DIR})")
        list(APPEND SIGNER_SOURCES src/ui/touchpad.cpp)
    else()
        message(STATUS "Touchpad support: NO - Qt QPA private headers not found. "
                       "A laptop touchpad will be driven as a touchscreen: taps "
                       "will work, the pointer will not move.")
    endif()
endif()

add_executable(btc_signer_gui ${SIGNER_SOURCES})
target_link_libraries(btc_signer_gui PRIVATE signer_core)
target_include_directories(btc_signer_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(SIGNEROS_BUILD_GUI)
    target_compile_definitions(btc_signer_gui PRIVATE SIGNEROS_GUI=1)
    target_link_libraries(btc_signer_gui PRIVATE
        Qt${SIGNEROS_QT_MAJOR}::Core
        Qt${SIGNEROS_QT_MAJOR}::Gui
        Qt${SIGNEROS_QT_MAJOR}::Widgets
    )
    if(SIGNEROS_WORD_SUGGESTIONS)
        target_compile_definitions(btc_signer_gui PRIVATE SIGNEROS_WORD_SUGGESTIONS=1)
    endif()
    if(SIGNEROS_QPA_INCLUDE_DIR)
        target_compile_definitions(btc_signer_gui PRIVATE SIGNEROS_TOUCHPAD=1)
        target_link_libraries(btc_signer_gui PRIVATE ${_qt_gui_private})
    endif()
endif()

# ---------------------------------------------------------------------------
# Shutdown-time free-memory scrub
# ---------------------------------------------------------------------------
add_executable(signeros-ramwipe src/tools/ramwipe.c)

# ---------------------------------------------------------------------------
install(TARGETS btc_signer_gui signeros-ramwipe RUNTIME DESTINATION bin)
