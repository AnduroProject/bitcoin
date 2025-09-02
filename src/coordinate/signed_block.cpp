
#include <coordinate/signed_block.h>
#include <hash.h>

uint256 SignedBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}