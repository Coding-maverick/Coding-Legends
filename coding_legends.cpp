#include <iostream>
#include <string>
#include <unordered_map>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <optional>
#include <regex>
#include <set>

using namespace std;

// -------------------- Utilities --------------------
string now_string() {
    auto t = chrono::system_clock::now();
    time_t tt = chrono::system_clock::to_time_t(t);
    stringstream ss;
    ss << put_time(gmtime(&tt), "%Y-%m-%d %H:%M:%S UTC");
    return ss.str();
}

string random_alphanum(size_t length = 32) {
    static const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static thread_local mt19937 rng(random_device{}());
    uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
    string s;
    s.reserve(length);
    for (size_t i = 0; i < length; ++i)
        s += charset[dist(rng)];
    return s;
}

string short_id() {
    return random_alphanum(10);
}

string simple_hash(const string &s) {
    uint64_t h = 1469598103934665603ull; // FNV offset
    for (unsigned char c : s)
        h = (h ^ c) * 1099511628211ull;
    stringstream ss;
    ss << hex << h;
    return ss.str();
}

// -------------------- PII Redaction --------------------
string redactPII(string text) {
    regex emailRegex(R"(([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,}))");
    text = regex_replace(text, emailRegex, "XXXXXXXXX");

    regex phoneRegex(R"((\+?\d[\d\s\-\(\)]{6,}\d))");
    text = regex_replace(text, phoneRegex, "XXXXXXXXX");

    regex idRegex(R"(\b(?=[A-Za-z]\d)(?=\d[A-Za-z])[A-Za-z0-9]{6,12}\b)");
    text = regex_replace(text, idRegex, "XXXXXXXXX");

    set<string> commonWords = {
        "i","am","the","this","that","and","my","he","she","it","is",
        "a","an","in","on","of","we","you","they","for","with","at",
        "to","from","by","as","are","be","was","were","have","has","had"
    };

    stringstream ss(text);
    string word, result = "";
    while (ss >> word) {
        string cleanWord = word;
        if (ispunct(cleanWord.back())) cleanWord.pop_back();

        string lower = cleanWord;
        for (auto &c : lower) c = tolower(c);

        if (commonWords.find(lower) == commonWords.end() && lower.length() > 2) {
            result += "XXXXXXXXX ";
        } else {
            result += word + " ";
        }
    }

    return result;
}

// -------------------- User Anonymity --------------------
class User {
public:
    string realUsername;
    string deviceFingerprint;
    string ipAddress;
    string visibleName;
    bool softAnonymous = false;
    bool deepAnonymous = false;

    User(string username, string fingerprint, string ip)
        : realUsername(username), deviceFingerprint(fingerprint),
          ipAddress(ip), visibleName(username) {}

    void enableSoftAnonymous() {
        softAnonymous = true;
        visibleName = generateAlias();
    }

    void enableDeepAnonymous() {
        deepAnonymous = true;
        softAnonymous = true;
        visibleName = generateAlias();
        deviceFingerprint = "Hidden";
        ipAddress = "Hidden";
    }

    void disableAnonymity() {
        softAnonymous = deepAnonymous = false;
        visibleName = realUsername;
    }

private:
    string generateAlias() {
        static const char charset[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        string alias = "Anon_";
        default_random_engine rng(random_device{}());
        uniform_int_distribution<> dist(0, sizeof(charset) - 2);
        for (int i = 0; i < 6; ++i)
            alias += charset[dist(rng)];
        return alias;
    }
};

// -------------------- Domain Types --------------------
struct Post {
    string id;
    string content;
    string category;
    string authorName;
    string secret_token_hash;
    bool flagged = false;
    bool deleted = false;
    string created_at;
};

struct DeletionRequest {
    string request_id;
    string post_id;
    double fee_amount;
    string created_at;
    bool payment_authorized = false;
    string payment_session_id;
    chrono::system_clock::time_point expires_at;
};

// -------------------- Payment Auth Wall --------------------
class PaymentAuthWall {
public:
    struct Session {
        string session_id;
        double amount;
        bool authorized = false;
        string created_at;
    };

    string create_session(double amount) {
        Session s;
        s.session_id = "sess_" + short_id();
        s.amount = amount;
        s.created_at = now_string();
        sessions_[s.session_id] = s;
        cout << "[Payment] Created session " << s.session_id << " for amount ₹" << amount << "\n";
        return s.session_id;
    }

    bool authorize_session(const string &session_id, const string &payment_token) {
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) return false;
        if (payment_token.empty()) return false;
        it->second.authorized = true;
        return true;
    }

    bool is_authorized(const string &session_id) const {
        auto it = sessions_.find(session_id);
        return (it != sessions_.end() && it->second.authorized);
    }

private:
    unordered_map<string, Session> sessions_;
};

// -------------------- Post Manager --------------------
class PostManager {
public:
    PostManager(double deletion_fee) : deletion_fee_(deletion_fee) {}

    pair<string,string> create_post(const string &content, const string &category, const string &author) {
        Post p;
        p.id = "post_" + short_id();
        p.content = content;
        p.category = category;
        p.authorName = author;
        string token = random_alphanum(48);
        p.secret_token_hash = simple_hash(token);
        p.created_at = now_string();
        posts_[p.id] = p;

        string secret_link = "https://confession.portal/magic-delete/" + token;
        cout << "[Create] Post " << p.id << " created under category #" << category << "\n";
        return {p.id, secret_link};
    }

    bool flag_post_by_token(const string &token) {
        string h = simple_hash(token);
        auto post_it = find_post_by_token_hash(h);
        if (!post_it || post_it->deleted) return false;
        post_it->flagged = true;
        return true;
    }

    optional<string> create_deletion_request_with_payment(const string &token, PaymentAuthWall &payment) {
        string h = simple_hash(token);
        auto post_it = find_post_by_token_hash(h);
        if (!post_it || post_it->deleted) return nullopt;

        DeletionRequest req;
        req.request_id = "delreq_" + short_id();
        req.post_id = post_it->id;
        req.fee_amount = deletion_fee_;
        req.created_at = now_string();
        req.payment_session_id = payment.create_session(req.fee_amount);
        req.expires_at = chrono::system_clock::now() + chrono::hours(24);

        deletion_requests_[req.request_id] = req;
        return req.request_id;
    }

    bool authorize_payment(const string &request_id, const string &payment_token, PaymentAuthWall &payment) {
        auto it = deletion_requests_.find(request_id);
        if (it == deletion_requests_.end()) return false;
        bool ok = payment.authorize_session(it->second.payment_session_id, payment_token);
        if (ok) it->second.payment_authorized = true;
        return ok;
    }

    bool admin_finalize_deletion(const string &request_id, PaymentAuthWall &payment) {
        auto it = deletion_requests_.find(request_id);
        if (it == deletion_requests_.end()) return false;
        if (!payment.is_authorized(it->second.payment_session_id)) return false;
        auto post_it = posts_.find(it->second.post_id);
        if (post_it == posts_.end()) return false;
        post_it->second.deleted = true;
        deletion_requests_.erase(it);
        return true;
    }

    void print_post(const string &post_id) const {
        auto it = posts_.find(post_id);
        if (it == posts_.end()) { cout << "[Info] Post not found\n"; return; }
        const Post &p = it->second;
        cout << "\nPost ID: " << p.id << "\n";
        cout << "Author: " << p.authorName << "\n";
        cout << "Category: #" << p.category << "\n";
        cout << "Content: " << p.content << "\n";
        cout << "Flagged: " << (p.flagged ? "yes" : "no") << "\n";
        cout << "Deleted: " << (p.deleted ? "yes" : "no") << "\n";
        cout << "Created: " << p.created_at << "\n";
    }

private:
    double deletion_fee_;
    unordered_map<string, Post> posts_;
    unordered_map<string, DeletionRequest> deletion_requests_;

    Post* find_post_by_token_hash(const string &hash) {
        for (auto &kv : posts_)
            if (kv.second.secret_token_hash == hash)
                return &kv.second;
        return nullptr;
    }
};

// -------------------- Demo --------------------
int main() {
    PostManager manager(250.0);
    PaymentAuthWall payment;

    string username, device, ip;
    cout << "Enter your username: ";
    getline(cin, username);
    cout << "Enter your device fingerprint: ";
    getline(cin, device);
    cout << "Enter your IP address: ";
    getline(cin, ip);

    User user(username, device, ip);

    int anonChoice;
    cout << "Choose anonymity mode:\n1. Normal\n2. Soft Anonymous\n3. Deep Anonymous\nChoice: ";
    cin >> anonChoice;
    cin.ignore();

    if (anonChoice == 2) user.enableSoftAnonymous();
    else if (anonChoice == 3) user.enableDeepAnonymous();

    cout << "\nVisible as: " << user.visibleName << "\n\n";

    string rawContent;
    cout << "Enter your confession:\n";
    getline(cin, rawContent);

    string safeContent = redactPII(rawContent);

    string category;
    cout << "Enter category (#Crushes, #ExamStress, #LostAndFound, etc.):\n";
    getline(cin, category);

    auto [post_id, secret_link] = manager.create_post(safeContent, category, user.visibleName);
    cout << "Post created! Secret deletion link: " << secret_link << "\n";

    // Simulate flagging
    string token = secret_link.substr(secret_link.find_last_of('/') + 1);
    manager.flag_post_by_token(token);

    // Simulate deletion
    auto req_id = manager.create_deletion_request_with_payment(token, payment);
    if (req_id) {
        manager.authorize_payment(*req_id, "card_ending_4242", payment);
        manager.admin_finalize_deletion(*req_id, payment);
    }

    manager.print_post(post_id);

    return 0;
}
