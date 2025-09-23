#ifndef BITCOIN_COORDINATEADDRESS_H
#define BITCOIN_COORDINATEADDRESS_H

#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

class CoordinateAddress
{
public:
    int32_t currentIndex;
    CoordinateAddress()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CoordinateAddress, obj) { READWRITE(obj.currentIndex); }
    void SetNull()
    {
        currentIndex = -1;
    }
};

#endif // BITCOIN_COORDINATEADDRESS_H