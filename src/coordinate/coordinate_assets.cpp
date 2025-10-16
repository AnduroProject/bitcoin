#include <coordinate/coordinate_assets.h>
#include <iomanip> 
#include <sstream> 
std::vector<unsigned char> CreateAssetId(uint64_t blockNumber, uint16_t assetIndex) {
    std::vector<unsigned char> assetId;

    // Convert blockNumber → 8 bytes (big-endian)
    for (int i = 0; i < 8; ++i) {
        assetId.push_back((blockNumber >> (56 - i * 8)) & 0xFF);
    }

    // Convert assetIndex → 3-digit string
    std::stringstream ss;
    ss << std::setw(3) << std::setfill('0') << assetIndex;
    std::string indexStr = ss.str();

    // Append string as ASCII bytes
    for (char c : indexStr) {
        assetId.push_back(static_cast<unsigned char>(c));
    }

    return assetId;
}

void ParseAssetId(const std::vector<unsigned char>& assetId, uint64_t &blockNumber, uint16_t &assetIndex) {
    if (assetId.size() != 11) {
        throw std::runtime_error("Invalid assetId length");
    }

    // Decode blockNumber (first 8 bytes, big-endian)
    blockNumber = 0;
    for (int i = 0; i < 8; ++i) {
        blockNumber = (blockNumber << 8) | assetId[i];
    }

    // Decode assetIndex (last 3 bytes as string)
    std::string indexStr(assetId.begin() + 8, assetId.end());
    assetIndex = static_cast<uint16_t>(std::stoi(indexStr));
}


uint256 getAssetHash(const std::vector<unsigned char>& assetId) {
    unsigned char bytes[32] = {0}; // uint256 requires 32 bytes

    size_t copySize = assetId.size();
    if (copySize > 32) copySize = 32; // truncate if too long

    // Copy bytes into the end of the array (big-endian padding)
    std::memcpy(bytes + (32 - copySize), assetId.data(), copySize);

    return uint256{bytes};
}
