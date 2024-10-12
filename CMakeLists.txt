cmake_minimum_required(VERSION 3.30)
project(Xylon)

set(CMAKE_CXX_STANDARD 23)

# Поиск пакетов через PkgConfig
find_package(PkgConfig REQUIRED)

# Подключение libsodium
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})

# Подключение libtorrent
pkg_check_modules(LIBTORRENT REQUIRED libtorrent-rasterbar)
include_directories(${LIBTORRENT_INCLUDE_DIRS})
link_directories(${LIBTORRENT_LIBRARY_DIRS})

# Поиск и подключение Boost
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

# Подключение FetchContent для WebRTC
include(FetchContent)

# Загрузка WebRTC
FetchContent_Declare(
        webrtc
        GIT_REPOSITORY https://webrtc.googlesource.com/src.git
        GIT_TAG main
)

FetchContent_MakeAvailable(webrtc)

# Указываем пути к WebRTC
include_directories(${webrtc_SOURCE_DIR}/sdk)
include_directories(${webrtc_SOURCE_DIR}/api)
include_directories(${webrtc_SOURCE_DIR}/rtc_base)
include_directories(${webrtc_SOURCE_DIR}/common_audio)  # Проверяем, если нужен этот модуль
include_directories(${webrtc_SOURCE_DIR}/modules)  # Проверяем, если нужен этот модуль
include_directories(${webrtc_SOURCE_DIR}/media)  # Проверяем, если нужен этот модуль
include_directories(${webrtc_SOURCE_DIR}/p2p)  # Для peer-to-peer

# Создаём исполняемый файл Xylon
add_executable(Xylon main.cpp)

# Линковка с нужными библиотеками
target_link_libraries(Xylon ${SODIUM_LIBRARIES} ${LIBTORRENT_LIBRARIES} ${Boost_LIBRARIES} -lwebrtc -lpthread)

