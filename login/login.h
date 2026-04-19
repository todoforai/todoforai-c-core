// todoforai-c-core/login — device login over Noise + credential storage
//
// Single-header library. Include in exactly one .c file with:
//   #define LOGIN_IMPLEMENTATION
//   #include "login.h"
//
// Requires: noise.h (from todoforai-c-core/noise/)

#ifndef LOGIN_H
#define LOGIN_H

#include <stddef.h>

#define LOGIN_CONFIG_MAX 4096

// Credential store — loaded from / saved to ~/.config/todoforai/credentials.json
typedef struct {
    char api_key[256];
    char browser_manager_noise_addr[256];
    char browser_manager_noise_public_key[128];
    char sandbox_manager_noise_addr[256];
    char sandbox_manager_noise_public_key[128];
} login_credentials_t;

// Load credentials from config file. Returns 0 on success, -1 if not found.
int login_load_credentials(login_credentials_t *creds);

// Save credentials to config file. Returns 0 on success, -1 on error.
int login_save_credentials(const login_credentials_t *creds);

// Get config file path. Writes to buf, returns 0 on success.
int login_config_path(char *buf, size_t cap);

// Run the full device login flow over Noise.
//   backend_addr: "host:port" of backend Noise server
//   backend_pub:  32-byte hex public key of backend Noise server
//   client_name:  e.g. "sandbox" or "browser"
// On success, saves credentials and returns 0.
int login_device_flow(const char *backend_addr, const char *backend_pub,
                      const char *client_name);

#endif // LOGIN_H


#ifdef LOGIN_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "noise.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <direct.h>
typedef SOCKET sock_t;
#define SOCK_INVALID INVALID_SOCKET
static void login_sock_init(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "error: WSAStartup failed\n");
    }
}
static void login_sock_close(sock_t s) { closesocket(s); }
#define login_sleep_ms(ms) Sleep(ms)
#define login_mkdir(p) _mkdir(p)
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pwd.h>
typedef int sock_t;
#define SOCK_INVALID (-1)
#define login_sock_init() ((void)0)
static void login_sock_close(sock_t s) { close(s); }
#define login_sleep_ms(ms) usleep((ms) * 1000)
#define login_mkdir(p) mkdir(p, 0700)
#endif

#define LOGIN_MAX_FRAME (1024 * 1024)

// ── Platform helpers ──────────────────────────────────────────────────────────

static int login_get_home(char *buf, size_t cap) {
#ifdef _WIN32
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, buf) == S_OK) return 0;
    const char *h = getenv("USERPROFILE");
    if (h) { snprintf(buf, cap, "%s", h); return 0; }
    return -1;
#else
    const char *h = getenv("HOME");
    if (h) { snprintf(buf, cap, "%s", h); return 0; }
    struct passwd *pw = getpwuid(getuid());
    if (pw) { snprintf(buf, cap, "%s", pw->pw_dir); return 0; }
    return -1;
#endif
}

int login_config_path(char *buf, size_t cap) {
    char home[512];
    if (login_get_home(home, sizeof(home)) < 0) return -1;
#ifdef _WIN32
    snprintf(buf, cap, "%s\\AppData\\Roaming\\todoforai\\credentials.json", home);
#elif defined(__APPLE__)
    snprintf(buf, cap, "%s/Library/Application Support/todoforai/credentials.json", home);
#else
    const char *xdg = getenv("XDG_CONFIG_HOME");
    if (xdg && xdg[0])
        snprintf(buf, cap, "%s/todoforai/credentials.json", xdg);
    else
        snprintf(buf, cap, "%s/.config/todoforai/credentials.json", home);
#endif
    return 0;
}

static void login_ensure_dir(const char *filepath) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", filepath);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            login_mkdir(tmp);
            *p = '/';
        }
    }
}

// ── Minimal JSON helpers (no dependencies) ────────────────────────────────────

// Detect "ok":false envelope tolerating whitespace around the colon.
static int json_envelope_is_error(const char *json) {
    const char *p = strstr(json, "\"ok\"");
    if (!p) return 0;
    p += 4;
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    return strncmp(p, "false", 5) == 0;
}

static const char *json_find_string(const char *json, const char *key, char *out, size_t cap) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) { out[0] = '\0'; return NULL; }
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == 'n' && strncmp(p, "null", 4) == 0) { out[0] = '\0'; return p; }
    if (*p != '"') { out[0] = '\0'; return NULL; }
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < cap) {
        if (*p == '\\' && p[1]) { p++; }
        out[i++] = *p++;
    }
    out[i] = '\0';
    return p;
}

// ── Credential I/O ────────────────────────────────────────────────────────────

int login_load_credentials(login_credentials_t *creds) {
    memset(creds, 0, sizeof(*creds));
    char path[1024];
    if (login_config_path(path, sizeof(path)) < 0) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char buf[LOGIN_CONFIG_MAX];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    json_find_string(buf, "apiKey", creds->api_key, sizeof(creds->api_key));
    json_find_string(buf, "browserManagerNoiseAddr", creds->browser_manager_noise_addr, sizeof(creds->browser_manager_noise_addr));
    json_find_string(buf, "browserManagerNoisePublicKey", creds->browser_manager_noise_public_key, sizeof(creds->browser_manager_noise_public_key));
    json_find_string(buf, "sandboxManagerNoiseAddr", creds->sandbox_manager_noise_addr, sizeof(creds->sandbox_manager_noise_addr));
    json_find_string(buf, "sandboxManagerNoisePublicKey", creds->sandbox_manager_noise_public_key, sizeof(creds->sandbox_manager_noise_public_key));
    return creds->api_key[0] ? 0 : -1;
}

// Write a JSON-escaped string value to file
static void json_write_escaped(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        switch (*s) {
            case '"':  fputs("\\\"", f); break;
            case '\\': fputs("\\\\", f); break;
            case '\n': fputs("\\n", f);  break;
            case '\r': fputs("\\r", f);  break;
            case '\t': fputs("\\t", f);  break;
            default:   fputc(*s, f);     break;
        }
    }
    fputc('"', f);
}

static void json_write_field(FILE *f, const char *key, const char *val, int *first) {
    if (!val[0]) return;
    if (!*first) fputs(",\n", f);
    fprintf(f, "  \"%s\": ", key);
    json_write_escaped(f, val);
    *first = 0;
}

int login_save_credentials(const login_credentials_t *creds) {
    // Merge: load existing, overwrite only non-empty fields from new creds
    login_credentials_t merged;
    if (login_load_credentials(&merged) < 0)
        memset(&merged, 0, sizeof(merged));
    if (creds->api_key[0])
        snprintf(merged.api_key, sizeof(merged.api_key), "%s", creds->api_key);
    if (creds->browser_manager_noise_addr[0])
        snprintf(merged.browser_manager_noise_addr, sizeof(merged.browser_manager_noise_addr), "%s", creds->browser_manager_noise_addr);
    if (creds->browser_manager_noise_public_key[0])
        snprintf(merged.browser_manager_noise_public_key, sizeof(merged.browser_manager_noise_public_key), "%s", creds->browser_manager_noise_public_key);
    if (creds->sandbox_manager_noise_addr[0])
        snprintf(merged.sandbox_manager_noise_addr, sizeof(merged.sandbox_manager_noise_addr), "%s", creds->sandbox_manager_noise_addr);
    if (creds->sandbox_manager_noise_public_key[0])
        snprintf(merged.sandbox_manager_noise_public_key, sizeof(merged.sandbox_manager_noise_public_key), "%s", creds->sandbox_manager_noise_public_key);

    char path[1024];
    if (login_config_path(path, sizeof(path)) < 0) return -1;
    login_ensure_dir(path);

    // Write to temp file, then rename for atomicity
    char tmp_path[1040];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;
#ifndef _WIN32
    chmod(tmp_path, 0600);
#endif
    int first = 1;
    fputs("{\n", f);
    json_write_field(f, "apiKey", merged.api_key, &first);
    json_write_field(f, "browserManagerNoiseAddr", merged.browser_manager_noise_addr, &first);
    json_write_field(f, "browserManagerNoisePublicKey", merged.browser_manager_noise_public_key, &first);
    json_write_field(f, "sandboxManagerNoiseAddr", merged.sandbox_manager_noise_addr, &first);
    json_write_field(f, "sandboxManagerNoisePublicKey", merged.sandbox_manager_noise_public_key, &first);
    fputs("\n}\n", f);
    fclose(f);
    if (rename(tmp_path, path) != 0) { remove(tmp_path); return -1; }
    return 0;
}

// ── TCP + Noise transport (reusable session) ──────────────────────────────────

static int login_hex_decode(uint8_t *out, size_t out_len, const char *hex) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void login_hex_encode(char *out, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02x", data[i]);
    out[len * 2] = '\0';
}

static int login_sock_recv_exact(sock_t fd, uint8_t *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        int n = recv(fd, (char *)buf + done, (int)(len - done), 0);
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static int login_sock_send_all(sock_t fd, const uint8_t *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        int n = send(fd, (const char *)buf + done, (int)(len - done), 0);
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static int login_write_frame(sock_t fd, const uint8_t *data, size_t len) {
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),  (uint8_t)len
    };
    if (login_sock_send_all(fd, hdr, 4) < 0) return -1;
    return login_sock_send_all(fd, data, len);
}

static int login_read_frame(sock_t fd, uint8_t **out, size_t *out_len) {
    uint8_t hdr[4];
    if (login_sock_recv_exact(fd, hdr, 4) < 0) return -1;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len == 0 || len > LOGIN_MAX_FRAME) return -1;
    *out = (uint8_t *)malloc(len);
    if (!*out) return -1;
    if (login_sock_recv_exact(fd, *out, len) < 0) { free(*out); return -1; }
    *out_len = len;
    return 0;
}

static sock_t login_tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return SOCK_INVALID;
    sock_t fd = SOCK_INVALID;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == SOCK_INVALID) continue;
        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        login_sock_close(fd);
        fd = SOCK_INVALID;
    }
    freeaddrinfo(res);
    return fd;
}

// Send a Noise-encrypted JSON request and receive the response.
// Returns decrypted response length, or -1 on error.
// Caller must free *resp_out.
static int login_noise_rpc(sock_t fd, noise_transport_t *transport,
                           const char *json, size_t json_len,
                           uint8_t **resp_out) {
    uint8_t *enc = (uint8_t *)malloc(json_len + 64);
    if (!enc) return -1;
    int enc_len = noise_transport_write(transport, enc, json_len + 64,
                                        (const uint8_t *)json, json_len);
    if (enc_len < 0) { free(enc); return -1; }
    if (login_write_frame(fd, enc, (size_t)enc_len) < 0) { free(enc); return -1; }
    free(enc);

    uint8_t *resp_enc;
    size_t resp_enc_len;
    if (login_read_frame(fd, &resp_enc, &resp_enc_len) < 0) return -1;
    *resp_out = (uint8_t *)malloc(resp_enc_len);
    if (!*resp_out) { free(resp_enc); return -1; }
    int resp_len = noise_transport_read(transport, *resp_out, resp_enc_len,
                                        resp_enc, resp_enc_len);
    free(resp_enc);
    if (resp_len < 0) { free(*resp_out); *resp_out = NULL; return -1; }
    return resp_len;
}

// ── Browser open ──────────────────────────────────────────────────────────────

static void login_open_browser(const char *url) {
#ifdef _WIN32
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
#else
    pid_t pid = fork();
    if (pid == 0) {
        // Child: redirect stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
#ifdef __APPLE__
        execlp("open", "open", url, (char *)NULL);
#else
        execlp("xdg-open", "xdg-open", url, (char *)NULL);
#endif
        _exit(127);
    }
    // Parent: don't wait — best-effort
#endif
}

// ── Noise connect + handshake helper ──────────────────────────────────────────

typedef struct {
    sock_t fd;
    noise_transport_t transport;
} login_session_t;

static int login_noise_connect(login_session_t *s, const char *host, const char *port_str,
                               const uint8_t remote_pub[32]) {
    s->fd = login_tcp_connect(host, port_str);
    if (s->fd == SOCK_INVALID) return -1;

    noise_handshake_t hs;
    noise_handshake_init(&hs, remote_pub);

    uint8_t m1_buf[256];
    int m1_len = noise_handshake_write(&hs, (const uint8_t *)"", 0, m1_buf, sizeof(m1_buf));
    if (m1_len < 0) { login_sock_close(s->fd); s->fd = SOCK_INVALID; return -1; }
    if (login_write_frame(s->fd, m1_buf, (size_t)m1_len) < 0) { login_sock_close(s->fd); s->fd = SOCK_INVALID; return -1; }

    uint8_t *m2_data;
    size_t m2_len;
    if (login_read_frame(s->fd, &m2_data, &m2_len) < 0) { login_sock_close(s->fd); s->fd = SOCK_INVALID; return -1; }
    uint8_t p2_buf[64];
    if (noise_handshake_read(&hs, m2_data, m2_len, p2_buf, sizeof(p2_buf)) < 0) {
        free(m2_data); login_sock_close(s->fd); s->fd = SOCK_INVALID; return -1;
    }
    free(m2_data);

    if (noise_handshake_split(&hs, &s->transport) < 0) { login_sock_close(s->fd); s->fd = SOCK_INVALID; return -1; }
    return 0;
}

// ── Device login flow ─────────────────────────────────────────────────────────

int login_device_flow(const char *backend_addr, const char *backend_pub,
                      const char *client_name) {
    login_sock_init();

    uint8_t remote_pub[32];
    if (login_hex_decode(remote_pub, 32, backend_pub) < 0) {
        fprintf(stderr, "error: invalid backend public key\n");
        return -1;
    }

    char host[256], port_str[16];
    const char *colon = strrchr(backend_addr, ':');
    if (!colon) { fprintf(stderr, "error: invalid backend address (missing port)\n"); return -1; }
    size_t hlen = (size_t)(colon - backend_addr);
    if (hlen >= sizeof(host)) { fprintf(stderr, "error: host too long\n"); return -1; }
    memcpy(host, backend_addr, hlen);
    host[hlen] = '\0';
    snprintf(port_str, sizeof(port_str), "%s", colon + 1);

    // Connect + handshake
    login_session_t session;
    if (login_noise_connect(&session, host, port_str, remote_pub) < 0) {
        fprintf(stderr, "error: cannot connect to %s\n", backend_addr);
        return -1;
    }

    // Step 1: cli.login.init
    uint8_t id_bytes[4];
    noise_random(id_bytes, 4);
    char id_hex[9];
    login_hex_encode(id_hex, id_bytes, 4);

    char init_req[512];
    snprintf(init_req, sizeof(init_req),
        "{\"id\":\"%s\",\"type\":\"cli.login.init\",\"payload\":{\"clientName\":\"%s\"}}",
        id_hex, client_name);

    uint8_t *init_resp;
    int init_resp_len = login_noise_rpc(session.fd, &session.transport, init_req, strlen(init_req), &init_resp);
    if (init_resp_len < 0) { login_sock_close(session.fd); fprintf(stderr, "error: init request failed\n"); return -1; }

    char resp_str[LOGIN_CONFIG_MAX];
    size_t copy_len = (size_t)init_resp_len < sizeof(resp_str) - 1 ? (size_t)init_resp_len : sizeof(resp_str) - 1;
    memcpy(resp_str, init_resp, copy_len);
    resp_str[copy_len] = '\0';
    free(init_resp);

    // Reject error envelopes ({"ok":false,"error":{...}}) before parsing fields,
    // otherwise json_find_string would pick up error.code as the device code.
    if (json_envelope_is_error(resp_str)) {
        char err_msg[256];
        json_find_string(resp_str, "message", err_msg, sizeof(err_msg));
        login_sock_close(session.fd);
        fprintf(stderr, "error: init failed: %s\n", err_msg[0] ? err_msg : resp_str);
        return -1;
    }

    char device_code[256], auth_url[1024];
    json_find_string(resp_str, "code", device_code, sizeof(device_code));
    json_find_string(resp_str, "url", auth_url, sizeof(auth_url));

    if (!device_code[0] || !auth_url[0]) {
        login_sock_close(session.fd);
        fprintf(stderr, "error: unexpected init response: %s\n", resp_str);
        return -1;
    }

    fprintf(stderr, "\n\033[1m\xf0\x9f\x94\x91 Open this URL to authorize:\033[0m\n");
    fprintf(stderr, "\033[36m%s\033[0m\n\n", auth_url);
    login_open_browser(auth_url);
    fprintf(stderr, "Waiting for approval (expires in 10min)...\n");

    // Step 2: Poll cli.login.poll (with reconnect on failure)
    int result = -1;
    for (int attempt = 0; attempt < 200; attempt++) { // 200 * 3s = 10min
        login_sleep_ms(3000);

        noise_random(id_bytes, 4);
        login_hex_encode(id_hex, id_bytes, 4);

        char poll_req[512];
        snprintf(poll_req, sizeof(poll_req),
            "{\"id\":\"%s\",\"type\":\"cli.login.poll\",\"payload\":{\"code\":\"%s\"}}",
            id_hex, device_code);

        uint8_t *poll_resp;
        int poll_resp_len = login_noise_rpc(session.fd, &session.transport, poll_req, strlen(poll_req), &poll_resp);
        if (poll_resp_len < 0) {
            // Connection lost — try to reconnect
            login_sock_close(session.fd);
            fprintf(stderr, "Reconnecting...\n");
            if (login_noise_connect(&session, host, port_str, remote_pub) < 0) {
                fprintf(stderr, "error: reconnect failed\n");
                return -1;
            }
            continue; // retry this poll on the new connection
        }

        copy_len = (size_t)poll_resp_len < sizeof(resp_str) - 1 ? (size_t)poll_resp_len : sizeof(resp_str) - 1;
        memcpy(resp_str, poll_resp, copy_len);
        resp_str[copy_len] = '\0';
        free(poll_resp);

        // Bail out on error envelopes instead of silently spinning for 10 minutes.
        if (json_envelope_is_error(resp_str)) {
            char err_msg[256];
            json_find_string(resp_str, "message", err_msg, sizeof(err_msg));
            fprintf(stderr, "\033[31merror: poll failed: %s\033[0m\n", err_msg[0] ? err_msg : resp_str);
            break;
        }

        char status[32];
        json_find_string(resp_str, "status", status, sizeof(status));

        if (strcmp(status, "complete") == 0) {
            login_credentials_t creds;
            memset(&creds, 0, sizeof(creds));
            json_find_string(resp_str, "apiKey", creds.api_key, sizeof(creds.api_key));
            json_find_string(resp_str, "browserManagerNoiseAddr", creds.browser_manager_noise_addr, sizeof(creds.browser_manager_noise_addr));
            json_find_string(resp_str, "browserManagerNoisePublicKey", creds.browser_manager_noise_public_key, sizeof(creds.browser_manager_noise_public_key));
            json_find_string(resp_str, "sandboxManagerNoiseAddr", creds.sandbox_manager_noise_addr, sizeof(creds.sandbox_manager_noise_addr));
            json_find_string(resp_str, "sandboxManagerNoisePublicKey", creds.sandbox_manager_noise_public_key, sizeof(creds.sandbox_manager_noise_public_key));

            if (!creds.api_key[0]) {
                fprintf(stderr, "error: approved but no API key in response\n");
                break;
            }

            if (login_save_credentials(&creds) < 0) {
                fprintf(stderr, "error: failed to save credentials\n");
                break;
            }

            char config_path[1024];
            login_config_path(config_path, sizeof(config_path));
            fprintf(stderr, "\033[32m\xe2\x9c\x85 Login successful! Credentials saved to %s\033[0m\n", config_path);
            result = 0;
            break;
        } else if (strcmp(status, "expired") == 0) {
            fprintf(stderr, "\033[31mLogin expired.\033[0m\n");
            break;
        }
        // status == "pending" → continue polling
    }

    login_sock_close(session.fd);
    return result;
}

#endif // LOGIN_IMPLEMENTATION
