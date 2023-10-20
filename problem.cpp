#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <openssl/evp.h>
using std::vector;
using std::string;


vector<unsigned char> compute_SHA256_hash(const std::string& file_path) {
    vector<unsigned char> hash;
    std::ifstream file(file_path, std::ios::binary);

    if (!file) {
        std::cerr << "Failed to open the file " << file_path << '.' << std::endl;
        return hash;
    }

    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);

    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        EVP_DigestUpdate(mdctx, buffer, file.gcount());
    }

    hash.resize(EVP_MD_size(md));
    EVP_DigestFinal_ex(mdctx, hash.data(), nullptr);

    EVP_MD_CTX_free(mdctx);

    return std::move(hash);
}

bool similar_files(const std::string& path1, const std::string& path2) {
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

bool very_different(const string& path1, const string& path2, int percentage) {
    std::ifstream stream1(path1, std::ios::binary | std::ios::ate);
    std::ifstream stream2(path2, std::ios::binary | std::ios::ate);

    if (!stream1.is_open() || !stream2.is_open()) {
        std::cerr << "Failed to open one of the files." << std::endl;
        return false;
    }
    
    if (std::min(stream1.tellg(), stream2.tellg()) >= percentage * std::max(stream1.tellg(), stream2.tellg())) {
        return false;
    }
    return true;
}

int similarity_percentage(const string& path1, const string& path2) {
    // TODO
    return 0;
}

void find_similarities(const string& dir_path1, const string& dir_path2, int sim_percentage) {
    vector<vector<unsigned char>> hashes1;
    vector<vector<unsigned char>> hashes2;
    vector<string> names1;
    vector<string> names2;

    // computing hashes for files and saving names.
    for (const auto &entry : std::filesystem::directory_iterator(dir_path1)) {
        if (std::filesystem::is_regular_file(entry)) {
            names1.push_back(entry.path().string());
            hashes1.push_back(compute_SHA256_hash(names1.back()));
        }
    }

    for (const auto &entry : std::filesystem::directory_iterator(dir_path2)) {
        if (std::filesystem::is_regular_file(entry)) {
            names2.push_back(entry.path().string());
            hashes2.push_back(compute_SHA256_hash(names2.back()));
        }
    }

    // checking for identical files.
    for (int i = 0; i < names1.size(); ++i) {
        for (int j = 0; j < names2.size(); ++j) {
            if (hashes1[i] != hashes2[j]) {
                continue;
            }
            if (similar_files(names1[i], names2[j])) {
                std::cout << dir_path1 << '/' << names1[i] << " - " << dir_path2 << '/' << names2[j] << "  files are identical." << std::endl;
                continue; 
            }
            if (very_different(names1[i], names2[j], sim_percentage)) {
                continue;
            }
            int perc = similarity_percentage(names1[i], names2[j]);
            if (perc > sim_percentage) {
                std::cout << dir_path1 << '/' << names1[i] << " - " << dir_path2 << '/' << names2[j] << "  files are identical." << std::endl;
            }
        }
    }
}

int main() {
    int sim_percentage;
    std::cin >> sim_percentage;
    string directory1;
    string directory2;
    std::cin >> directory1 >> directory2;

    find_similarities(directory1, directory2, sim_percentage);

    return 0;
}