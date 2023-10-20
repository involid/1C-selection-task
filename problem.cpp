#include <cmath>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <openssl/evp.h>
#include <string>
#include <vector>
using std::string;
using std::vector;

const size_t MaxChunkSize = (1 << 10);
std::hash<string> hasher;

size_t computeSHA256Hash(const string& data)
{
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname("sha256");

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, data.c_str(), data.length());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    char hexHash[2 * md_len + 1];
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(&hexHash[2 * i], "%02x", md_value[i]);
    }

    return hasher(hexHash);
}

vector<size_t>
compute_hashes(const string& filePath, size_t chunk_size = (1 << 12))
{
    vector<size_t> hashes;
    std::ifstream file(filePath);

    if (!file.is_open()) {
        std::cerr << "Failed to open " << filePath << std::endl;
        return hashes;
    }

    string chunk;
    char buffer;
    while (file.get(buffer)) {
        chunk += buffer;
        if (chunk.length() >= chunk_size) {
            size_t hash = computeSHA256Hash(chunk);
            hashes.push_back(hash);
            chunk.clear();
        }
    }

    if (!chunk.empty()) {
        size_t hash = computeSHA256Hash(chunk);
        hashes.push_back(hash);
    }

    return hashes;
}

bool similar_files(const std::string& path1, const std::string& path2)
{
    std::ifstream stream1(path1, std::ios::binary | std::ios::ate);
    std::ifstream stream2(path2, std::ios::binary | std::ios::ate);

    if (!stream1.is_open() || !stream2.is_open()) {
        std::cerr << "Failed to open one of the files." << std::endl;
        return false;
    }

    if (stream1.tellg() != stream2.tellg()) {
        return false;
    }

    stream1.seekg(0);
    stream2.seekg(0);

    char byte1, byte2;
    while (stream1.get(byte1) && stream2.get(byte2)) {
        if (byte1 != byte2) {
            return false;
        }
    }

    return true;
}

size_t min(size_t a, size_t b, size_t c)
{
    return std::min(std::min(a, b), c);
}

template <typename T> size_t levenshtein_distance(const T& s1, const T& s2)
{
    size_t len1 = s1.size();
    size_t len2 = s2.size();

    vector<vector<size_t>> dp(len1 + 1, vector<size_t>(len2 + 1, 0));

    for (size_t i = 0; i <= len1; ++i) {
        dp[i][0] = i;
    }
    for (size_t j = 0; j <= len2; ++j) {
        dp[0][j] = j;
    }

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            size_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            dp[i][j] = min(
                dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
        }
    }

    return dp[len1][len2];
}

void find_similarities(
    const string& dir_path1,
    const string& dir_path2,
    int sim_percentage)
{
    vector<string> names1;
    vector<string> names2;
    vector<size_t> sizes1;
    vector<size_t> sizes2;

    // computing hashes for files and saving names.
    for (const auto& entry : std::filesystem::directory_iterator(dir_path1)) {
        if (std::filesystem::is_regular_file(entry)) {
            names1.push_back(entry.path().string());
            sizes1.push_back(file_size(entry));
        }
    }

    for (const auto& entry : std::filesystem::directory_iterator(dir_path2)) {
        if (std::filesystem::is_regular_file(entry)) {
            names2.push_back(entry.path().string());
            sizes2.push_back(file_size(entry));
        }
    }

    vector<vector<double>> similarities(names1.size());
    vector<bool> found_similar1(names1.size(), false);
    vector<bool> found_similar2(names2.size(), false);
    // checking for identical files.
    // then checking if they are very different
    // then finding similarity percentages
    for (int i = 0; i < names1.size(); ++i) {
        similarities[i].resize(names2.size());
        for (int j = 0; j < names2.size(); ++j) {
            similarities[i][j] = 0;
            if (similar_files(names1[i], names2[j])) {
                std::cout << names1[i] << " - " << names2[j]
                          << " files are identical." << std::endl;
                found_similar1[i] = true;
                found_similar2[j] = true;
                continue;
            }
            if (std::min(sizes1[i], sizes2[j]) * 100 <
                std::max(sizes1[i], sizes2[j]) * sim_percentage) {
                continue;
            }
            double perc;
            size_t chunk_size =
                std::max(sizes1[i], sizes2[j]) / MaxChunkSize + 1;
            auto hash1 = compute_hashes(names1[i], chunk_size);
            auto hash2 = compute_hashes(names2[j], chunk_size);
            perc = static_cast<double>(levenshtein_distance(hash1, hash2)) /
                   std::max(hash1.size(), hash2.size()) * 100;
            similarities[i][j] = perc * std::min(sizes1[i], sizes2[j]) /
                                 std::max(sizes1[i], sizes2[j]);
        }
    }

    for (int i = 0; i < names1.size(); ++i) {
        for (int j = 0; j < names2.size(); ++j) {
            if (similarities[i][j] >= sim_percentage) {
                std::cout << names1[i] << " - " << names2[j]
                          << "  files are identical with " << similarities[i][j]
                          << "%" << std::endl;
                found_similar1[i] = true;
                found_similar2[j] = true;
            }
        }
    }

    for (int i = 0; i < names1.size(); ++i) {
        if (!found_similar1[i]) {
            std::cout << names1[i] << " is not in " << dir_path2 << std::endl;
        }
    }
    for (int i = 0; i < names2.size(); ++i) {
        if (!found_similar2[i]) {
            std::cout << names2[i] << " is not in " << dir_path1 << std::endl;
        }
    }
}

int main()
{
    double sim_percentage;
    std::cin >> sim_percentage;
    string directory1;
    string directory2;
    std::cin >> directory1 >> directory2;

    find_similarities(directory1, directory2, sim_percentage);

    return 0;
}