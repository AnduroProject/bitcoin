#include <iostream>
#include <serialize.h>
#include <uint256.h>

template<typename Stream, typename CoordinateType>
inline void UnserializeAsset(CoordinateType& assetData, Stream& s) {
    s >> assetData.nID;
    s >> assetData.assetType;
    s >> assetData.precision;
    s >> assetData.strTicker;
    s >> assetData.strHeadline;
    s >> assetData.payload;
    s >> assetData.txid;
    s >> assetData.nSupply;
    s >> assetData.strController;
    s >> assetData.strOwner;
}

template<typename Stream, typename CoordinateType>
inline void SerializeAsset(const CoordinateType& assetData, Stream& s) {
    s << assetData.nID;
    s << assetData.assetType;
    s << assetData.precision;
    s << assetData.strTicker;
    s << assetData.strHeadline;
    s << assetData.payload;
    s << assetData.txid;
    s << assetData.nSupply;
    s << assetData.strController;
    s << assetData.strOwner;
}

struct CoordinateAsset {
public:
    std::vector<unsigned char> nID;  /*!< Asset unique buffer  */
    uint32_t assetType;        /*!< Asset type - (e.g. 0 - tokens, 1 - nft, 1 - blob nft) */
    uint32_t precision;        /*!< Precision Number - (0..8) */
    std::string strTicker;     /*!< Asset symbol. */
    std::string strHeadline;   /*!< Asset name. */
    uint256 payload;           /*!< Asset sha256 id combination for all asset information with asset data. */
    uint256 txid;              /*!< Asset gensis id when the asset is newly minted */
    uint64_t nSupply;          /*!< Asset current supply */
    std::string strController; /*!< Asset controller details, which used to mint additionally */
    std::string strOwner; /*!< Asset owner at the time of creating asset */

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeAsset(*this, s);
    }

    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeAsset(*this, s);
    }

    template <typename Stream>
    CoordinateAsset(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    CoordinateAsset() {
        SetNull();
    }

    void SetNull()
    {
        nID.clear();
        assetType = 0;
        precision = 0;
        strTicker = "";
        strHeadline = "";
        payload = uint256{};
        txid = uint256{};
        nSupply = 0;
        strController = "";
        strOwner = "";
    }
};

std::vector<unsigned char> CreateAssetId(uint64_t blockNumber, uint16_t assetIndex);
void ParseAssetId(const std::vector<unsigned char>& assetId, uint64_t &blockNumber, uint16_t &assetIndex);
uint256 getAssetHash(const std::vector<unsigned char>& assetId);