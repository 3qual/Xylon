#include <iostream>
#include <string>
#include <sodium.h>
#include <libtorrent/session.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/entry.hpp>
#include <libtorrent/bencode.hpp>
#include <libtorrent/sha1_hash.hpp>
#include "webrtc/api/peer_connection_interface.h"
#include "rtc_base/thread.h"

// Генерация цифровой подписи
std::string sign_data(const std::string& data, const std::string& private_key) {
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, nullptr, reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
                         reinterpret_cast<const unsigned char*>(private_key.c_str()));

    return std::string(reinterpret_cast<char*>(signature), crypto_sign_BYTES);
}

// Проверка цифровой подписи
bool verify_signature(const std::string& data, const std::string& signature, const std::string& public_key) {
    return crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(signature.c_str()),
                                       reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
                                       reinterpret_cast<const unsigned char*>(public_key.c_str())) == 0;
}

// Шифрование данных
std::string encrypt_data(const std::string& data, const std::string& shared_key) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[data.size() + crypto_secretbox_MACBYTES];

    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(ciphertext, reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
                          nonce, reinterpret_cast<const unsigned char*>(shared_key.c_str()));

    std::string encrypted_data(reinterpret_cast<char*>(nonce), crypto_secretbox_NONCEBYTES);
    encrypted_data += std::string(reinterpret_cast<char*>(ciphertext), data.size() + crypto_secretbox_MACBYTES);

    return encrypted_data;
}

// Расшифровка данных
std::string decrypt_data(const std::string& encrypted_data, const std::string& shared_key) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    std::copy(encrypted_data.begin(), encrypted_data.begin() + crypto_secretbox_NONCEBYTES, nonce);

    std::string ciphertext = encrypted_data.substr(crypto_secretbox_NONCEBYTES);
    unsigned char decrypted_data[ciphertext.size() - crypto_secretbox_MACBYTES];

    if (crypto_secretbox_open_easy(decrypted_data, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.size(),
                                   nonce, reinterpret_cast<const unsigned char*>(shared_key.c_str())) != 0) {
        throw std::runtime_error("Decryption failed!");
    }

    return std::string(reinterpret_cast<char*>(decrypted_data), ciphertext.size() - crypto_secretbox_MACBYTES);
}

// Класс для работы с WebRTC и DHT
class DHTWebRTCClient {
public:
    lt::session& session;

    DHTWebRTCClient(lt::session& sess) : session(sess) {}

    // Публикация SDP или ICE кандидатов в DHT
    void publish_webrtc_data(const std::string& key, const std::string& sdp_data) {
        lt::entry e;
        e["webrtc"] = sdp_data;

        std::vector<char> buffer;
        lt::bencode(std::back_inserter(buffer), e);

        lt::sha1_hash hash = lt::hasher(key.c_str(), key.size()).final();
        session.dht_put_item(hash, buffer);
        std::cout << "Published WebRTC data in DHT with key: " << key << std::endl;
    }

    // Получение SDP или ICE кандидатов из DHT
    void get_webrtc_data(const std::string& key, std::function<void(const std::string&)> callback) {
        lt::sha1_hash hash = lt::hasher(key.c_str(), key.size()).final();
        session.dht_get_item(hash, [callback](lt::entry const& e, std::array<char, 32> const&, bool) {
            if (e.type() == lt::entry::dictionary_t && e.find_key("webrtc")) {
                std::string sdp_data = e.dict_find_string_value("webrtc");
                callback(sdp_data);
            } else {
                std::cout << "No WebRTC data found for key: " << key << std::endl;
            }
        });
    }
};

// Класс WebRTC для P2P соединений
class WebRTCClient : public webrtc::PeerConnectionObserver, public webrtc::DataChannelObserver {
public:
    rtc::scoped_refptr<webrtc::PeerConnectionInterface> peer_connection_;
    rtc::scoped_refptr<webrtc::DataChannelInterface> data_channel_;
    DHTWebRTCClient* dht_client;
    std::string local_nick;
    std::string remote_nick;

    WebRTCClient(DHTWebRTCClient* dht, const std::string& local, const std::string& remote)
        : dht_client(dht), local_nick(local), remote_nick(remote) {}

    // Когда SDP готов, публикуем его в DHT
    void OnLocalDescription(webrtc::SessionDescriptionInterface* desc) {
        std::string sdp;
        desc->ToString(&sdp);
        dht_client->publish_webrtc_data(local_nick, sdp);  // Публикуем SDP в DHT
    }

    // Когда найден ICE кандидат, публикуем его в DHT
    void OnIceCandidate(const webrtc::IceCandidateInterface* candidate) override {
        std::string candidate_string;
        candidate->ToString(&candidate_string);
        dht_client->publish_webrtc_data(local_nick, candidate_string);  // Публикуем ICE кандидата в DHT
    }

    // Создание и открытие DataChannel
    void CreateDataChannel() {
        webrtc::DataChannelInit config;
        data_channel_ = peer_connection_->CreateDataChannel("dataChannel", &config);
        data_channel_->RegisterObserver(this);
    }

    // Когда DataChannel открыт, можем отправлять сообщения
    void OnStateChange() override {
        if (data_channel_->state() == webrtc::DataChannelInterface::DataState::kOpen) {
            std::cout << "DataChannel is open. Ready to send messages." << std::endl;
        }
    }

    // Обработка входящих сообщений
    void OnMessage(const webrtc::DataBuffer& buffer) override {
        std::string message(buffer.data.data<char>(), buffer.data.size());
        std::cout << "Message received from " << remote_nick << ": " << message << std::endl;
    }

    // Отправка сообщения через DataChannel
    void SendMessage(const std::string& message) {
        if (data_channel_ && data_channel_->state() == webrtc::DataChannelInterface::DataState::kOpen) {
            webrtc::DataBuffer buffer(rtc::CopyOnWriteBuffer(message.c_str(), message.size()), true);
            data_channel_->Send(buffer);
        }
    }

    // Установка удаленного SDP, полученного из DHT
    void SetRemoteDescription(const std::string& sdp_data) {
        webrtc::SdpParseError error;
        std::unique_ptr<webrtc::SessionDescriptionInterface> remote_desc = webrtc::CreateSessionDescription(webrtc::SdpType::kOffer, sdp_data, &error);
        peer_connection_->SetRemoteDescription(std::move(remote_desc));
    }
};

// Инициализация WebRTC соединения
void InitWebRTCConnection(rtc::Thread* network_thread, rtc::Thread* signaling_thread, WebRTCClient& client) {
    webrtc::PeerConnectionInterface::RTCConfiguration config;
    config.servers.push_back({"stun:stun.l.google.com:19302"});  // STUN сервер для обхода NAT

    rtc::scoped_refptr<webrtc::PeerConnectionFactoryInterface> peer_connection_factory =
        webrtc::CreatePeerConnectionFactory(network_thread, nullptr, signaling_thread, nullptr, nullptr, nullptr, nullptr, nullptr);

    client.peer_connection_ = peer_connection_factory->CreatePeerConnection(config, nullptr, nullptr, &client);

    // Создаем SDP offer и публикуем его
    client.peer_connection_->CreateOffer([&client](webrtc::SessionDescriptionInterface* offer) {
        client.peer_connection_->SetLocalDescription(offer);
        client.OnLocalDescription(offer);
    });

    client.CreateDataChannel();
}

// Основная программа
int main() {
    // Инициализация libsodium
    if (sodium_init() < 0) {
        std::cerr << "Libsodium initialization failed!" << std::endl;
        return -1;
    }

    // Инициализация DHT
    lt::session session;
    lt::settings_pack settings;
    settings.set_bool(lt::settings_pack::enable_dht, true);
    session.apply_settings(settings);

    // Добавляем bootstrap узлы DHT
    session.add_dht_router(std::make_pair("router.bittorrent.com", 6881));
    session.add_dht_router(std::make_pair("router.utorrent.com", 6881));
    session.add_dht_router(std::make_pair("dht.transmissionbt.com", 6881));

    // WebRTC client
    DHTWebRTCClient dht_client(session);
    rtc::Thread* network_thread = rtc::Thread::Create().release();
    network_thread->Start();
    rtc::Thread* signaling_thread = rtc::Thread::Create().release();
    signaling_thread->Start();

    WebRTCClient client(&dht_client, "user1_nick", "user2_nick");

    InitWebRTCConnection(network_thread, signaling_thread, client);

    // Ожидание сообщений и ввод
    std::string message;
    std::cout << "Enter message to send: ";
    std::getline(std::cin, message);
    client.SendMessage(message);

    std::this_thread::sleep_for(std::chrono::seconds(10));  // Ожидание завершения обмена сообщениями

    return 0;
}

