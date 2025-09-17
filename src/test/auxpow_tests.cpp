// Copyright (c) 2014-2024 Daniel Kraft
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <auxpow.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <validation.h>
#include <pow.h>
#include <primitives/block.h>
#include <rpc/auxpow_miner.h>
#include <script/script.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <uint256.h>
#include <univalue.h>

#include <test/util/setup_common.h>
#include <test/util/txmempool.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

/* No space between BOOST_AUTO_TEST_SUITE and '(', so that extraction of
   the test-suite name works with grep as done in the Makefile.  */
BOOST_AUTO_TEST_SUITE(auxpow_tests)

typedef std::vector<unsigned char> valtype;

/* ************************************************************************** */

/**
 * Tamper with a uint256 (modify it).
 * @param num The number to modify.
 */
static void
tamperWith (uint256& num)
{
  arith_uint256 modifiable = UintToArith256 (num);
  modifiable += 1;
  num = ArithToUint256 (modifiable);
}

/**
 * Helper class that is friend to CAuxPow and makes the internals accessible
 * to the test code.
 */
class CAuxPowForTest : public CAuxPow
{

public:

  explicit inline CAuxPowForTest (CTransactionRef txIn)
    : CAuxPow (std::move (txIn))
  {}

  using CAuxPow::coinbaseTx;
  using CAuxPow::vMerkleBranch;
  using CAuxPow::vChainMerkleBranch;
  using CAuxPow::nChainIndex;
  using CAuxPow::parentBlock;

  using CAuxPow::CheckMerkleBranch;

};

/**
 * Utility class to construct auxpow's and manipulate them.  This is used
 * to simulate various scenarios.
 */
class CAuxpowBuilder
{
public:

  /** The parent block (with coinbase, not just header).  */
  CBlock parentBlock;

  /** The auxpow's merkle branch (connecting it to the coinbase).  */
  std::vector<uint256> auxpowChainMerkleBranch;
  /** The auxpow's merkle tree index.  */
  int auxpowChainIndex;

  /**
   * Initialise everything.
   * @param baseVersion The parent block's base version to use.
   * @param chainId The parent block's chain ID to use.
   */
  CAuxpowBuilder (int baseVersion, int chainId);

  /**
   * Set the coinbase's script.
   * @param scr Set it to this script.
   */
  void setCoinbase (const CScript& scr);

  /**
   * Build the auxpow merkle branch.  The member variables will be
   * set accordingly.  This has to be done before constructing the coinbase
   * itself (which must contain the root merkle hash).  When we have the
   * coinbase afterwards, the member variables can be used to initialise
   * the CAuxPow object from it.
   * @param hashAux The merge-mined chain's block hash.
   * @param h Height of the merkle tree to build.
   * @param index Index to use in the merkle tree.
   * @return The root hash, with reversed endian.
   */
  valtype buildAuxpowChain (const uint256& hashAux, unsigned h, int index);

  /**
   * Build the finished CAuxPow object.  We assume that the auxpowChain
   * member variables are already set.  We use the passed in transaction
   * as the base.  It should (probably) be the parent block's coinbase.
   * @param tx The base tx to use.
   * @return The constructed CAuxPow object.
   */
  CAuxPow get (const CTransactionRef tx) const;

  /**
   * Build the finished CAuxPow object from the parent block's coinbase.
   * @return The constructed CAuxPow object.
   */
  inline CAuxPow
  get () const
  {
    assert (!parentBlock.vtx.empty ());
    return get (parentBlock.vtx[0]);
  }

  /**
   * Returns the finished CAuxPow object and returns it as std::unique_ptr.
   */
  inline std::unique_ptr<CAuxPow>
  getUnique () const
  {
    return std::unique_ptr<CAuxPow>(new CAuxPow (get ()));
  }

  /**
   * Build a data vector to be included in the coinbase.  It consists
   * of the aux hash, the merkle tree size and the nonce.  Optionally,
   * the header can be added as well.
   * @param header Add the header?
   * @param hashAux The aux merkle root hash.
   * @param h Height of the merkle tree.
   * @param nonce The nonce value to use.
   * @return The constructed data.
   */
  static valtype buildCoinbaseData (bool header, const valtype& auxRoot,
                                    unsigned h, int nonce);

};

CAuxpowBuilder::CAuxpowBuilder (int baseVersion, int chainId)
  : auxpowChainIndex(-1)
{
  parentBlock.SetBaseVersion(baseVersion, chainId);
}

void
CAuxpowBuilder::setCoinbase (const CScript& scr)
{
  CMutableTransaction mtx;
  
  // Set up input
  mtx.vin.resize (1);
  mtx.vin[0].prevout.SetNull ();
  mtx.vin[0].scriptSig = CScript(); // Empty script or whatever you need for input
  
  // Set up outputs - resize to at least 3 outputs
  mtx.vout.resize (3);
  
  mtx.vout[2].scriptPubKey = scr;
  mtx.vout[2].nValue = 0; // Set appropriate value
  
  parentBlock.vtx.clear ();
  parentBlock.vtx.push_back (MakeTransactionRef (std::move (mtx)));
  parentBlock.hashMerkleRoot = BlockRawMerkleRoot (parentBlock, 0);
}


valtype
CAuxpowBuilder::buildAuxpowChain (const uint256& hashAux, unsigned h, int index)
{
  auxpowChainIndex = index;

  /* Just use "something" for the branch.  Doesn't really matter.  */
  auxpowChainMerkleBranch.clear ();
  for (unsigned i = 0; i < h; ++i)
    auxpowChainMerkleBranch.push_back (ArithToUint256 (arith_uint256 (i)));

  const uint256 hash
    = CAuxPowForTest::CheckMerkleBranch (hashAux, auxpowChainMerkleBranch,
                                         index);

  valtype res = ToByteVector (hash);
  std::reverse (res.begin (), res.end ());

  return res;
}

CAuxPow
CAuxpowBuilder::get (const CTransactionRef tx) const
{
  LOCK(cs_main);

  CAuxPowForTest res(tx);
  res.vMerkleBranch = TransactionMerklePath (parentBlock, 0);

  res.vChainMerkleBranch = auxpowChainMerkleBranch;
  res.nChainIndex = auxpowChainIndex;
  res.parentBlock = parentBlock;

  return res;
}

valtype
CAuxpowBuilder::buildCoinbaseData (bool header, const valtype& auxRoot,
                                   unsigned h, int nonce)
{
  valtype res;

  if (header)
    res.insert (res.end (),
                pchMergedMiningHeader,
                pchMergedMiningHeader + sizeof (pchMergedMiningHeader));
  res.insert (res.end (), auxRoot.begin (), auxRoot.end ());

  int size = (1 << h);
  for (int i = 0; i < 4; ++i)
    {
      res.insert (res.end (), size & 0xFF);
      size >>= 8;
    }
  for (int i = 0; i < 4; ++i)
    {
      res.insert (res.end (), nonce & 0xFF);
      nonce >>= 8;
    }

  return res;
}

/* ************************************************************************** */

BOOST_FIXTURE_TEST_CASE (check_auxpow, BasicTestingSetup)
{
  const Consensus::Params& params = Params ().GetConsensus ();
  CAuxpowBuilder builder(5, 42);
  CAuxPow auxpow;

  const uint256 hashAux = ArithToUint256 (arith_uint256(12345));
  const int32_t ourChainId = params.nAuxpowChainId;
  const unsigned height = 30;
  const int nonce = 7;
  int index;

  valtype auxRoot, data;
  CScript scr;

  /* Build a correct auxpow.  The height is the maximally allowed one.  */
  index = CAuxPow::getExpectedIndex (nonce, ourChainId, height);
  auxRoot = builder.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  scr = (CScript () << 2809 << 2013);
  scr = (scr << OP_2 << data);
  builder.setCoinbase (scr);
  BOOST_CHECK (builder.get ().check (hashAux, ourChainId, params));

  /* An auxpow without any inputs in the parent coinbase tx should be
     handled gracefully (and be considered invalid).  */
  CMutableTransaction mtx(*builder.parentBlock.vtx[0]);
  mtx.vin.clear ();
  mtx.vout.clear ();
  builder.parentBlock.vtx.clear ();
  builder.parentBlock.vtx.push_back (MakeTransactionRef (std::move (mtx)));
  builder.parentBlock.hashMerkleRoot = BlockRawMerkleRoot (builder.parentBlock,0);
  BOOST_CHECK (!builder.get ().check (hashAux, ourChainId, params));

  /* Check that the auxpow is invalid if we change either the aux block's
     hash or the chain ID.  */
  uint256 modifiedAux(hashAux);
  tamperWith (modifiedAux);
  BOOST_CHECK (!builder.get ().check (modifiedAux, ourChainId, params));
  BOOST_CHECK (!builder.get ().check (hashAux, ourChainId + 1, params));

  /* Non-coinbase parent tx should fail.  Note that we can't just copy
     the coinbase literally, as we have to get a tx with different hash.  */
  const CTransactionRef oldCoinbase = builder.parentBlock.vtx[0];
  builder.setCoinbase (scr << 5);
  builder.parentBlock.vtx.push_back (oldCoinbase);
  builder.parentBlock.hashMerkleRoot = BlockRawMerkleRoot (builder.parentBlock,0);
  auxpow = builder.get (builder.parentBlock.vtx[0]);
  BOOST_CHECK (auxpow.check (hashAux, ourChainId, params));
  auxpow = builder.get (builder.parentBlock.vtx[1]);
  BOOST_CHECK (!auxpow.check (hashAux, ourChainId, params));

  /* The parent chain can't have the same chain ID.  */
  CAuxpowBuilder builder2(builder);
  builder2.parentBlock.SetChainId (100);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  builder2.parentBlock.SetChainId (ourChainId);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Disallow too long merkle branches.  */
  builder2 = builder;
  index = CAuxPow::getExpectedIndex (nonce, ourChainId, height + 1);
  auxRoot = builder2.buildAuxpowChain (hashAux, height + 1, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height + 1, nonce);
  scr = (CScript () << 2809 << 2013);
  scr = (scr << OP_2 << data);
  builder2.setCoinbase (scr);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Verify that we compare correctly to the parent block's merkle root.  */
  builder2 = builder;
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  tamperWith (builder2.parentBlock.hashMerkleRoot);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Build a non-header legacy version and check that it is also accepted.  */
  builder2 = builder;
  index = CAuxPow::getExpectedIndex (nonce, ourChainId, height);
  auxRoot = builder2.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (false, auxRoot, height, nonce);
  scr = (CScript () << 2809 << 2013);
  scr = (scr << OP_2 << data);
  builder2.setCoinbase (scr);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));

  /* However, various attempts at smuggling two roots in should be detected.  */

  const valtype wrongAuxRoot
    = builder2.buildAuxpowChain (modifiedAux, height, index);
  valtype data2
    = CAuxpowBuilder::buildCoinbaseData (false, wrongAuxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data2 = CAuxpowBuilder::buildCoinbaseData (true, wrongAuxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data2 = CAuxpowBuilder::buildCoinbaseData (false, wrongAuxRoot,
                                             height, nonce);
  builder2.setCoinbase (CScript () << data << data2);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
  builder2.setCoinbase (CScript () << data2 << data);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));

  /* Verify that the appended nonce/size values are checked correctly.  */

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));

  data.pop_back ();
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height - 1, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce + 3);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  /* Put the aux hash in an invalid merkle tree position.  */

  auxRoot = builder.buildAuxpowChain (hashAux, height, index + 1);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (!builder2.get ().check (hashAux, ourChainId, params));

  auxRoot = builder.buildAuxpowChain (hashAux, height, index);
  data = CAuxpowBuilder::buildCoinbaseData (true, auxRoot, height, nonce);
  builder2.setCoinbase (CScript () << data);
  BOOST_CHECK (builder2.get ().check (hashAux, ourChainId, params));
}



BOOST_AUTO_TEST_SUITE_END ()
