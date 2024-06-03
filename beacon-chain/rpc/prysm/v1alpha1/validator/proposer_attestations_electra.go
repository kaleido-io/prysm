package validator

import (
	"slices"

	"github.com/prysmaticlabs/go-bitfield"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/blocks"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// computeOnChainAggregate constructs an on chain final aggregate form a list of network aggregates with equal attestation data.
// It assumes that each network aggregate has exactly one committee bit set.
// The spec defines how to construct a final aggregate from one set of network aggregates, but computeOnChainAggregate does this
// for any number of such sets (these sets are bundled together in the map argument).
//
// Spec definition:
//
//	def compute_on_chain_aggregate(network_aggregates: Sequence[Attestation]) -> Attestation:
//		aggregates = sorted(network_aggregates, key=lambda a: get_committee_indices(a.committee_bits)[0])
//
//		data = aggregates[0].data
//		aggregation_bits = Bitlist[MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT]()
//		for a in aggregates:
//			for b in a.aggregation_bits:
//				aggregation_bits.append(b)
//
//		signature = bls.Aggregate([a.signature for a in aggregates])
//
//		committee_indices = [get_committee_indices(a.committee_bits)[0] for a in aggregates]
//		committee_flags = [(index in committee_indices) for index in range(0, MAX_COMMITTEES_PER_SLOT)]
//		committee_bits = Bitvector[MAX_COMMITTEES_PER_SLOT](committee_flags)
//
//		return Attestation(
//			aggregation_bits=aggregation_bits,
//			data=data,
//			committee_bits=committee_bits,
//			signature=signature,
//		)
func computeOnChainAggregate(aggregates map[blocks.AttestationId][]blocks.ROAttestation) ([]blocks.ROAttestation, error) {
	// Digest is the attestation data root. The incoming map has attestations for the same root
	// but different committee indices under different keys. We create a new map where the digest is the key
	// so that all attestations for the same root are under one key.
	aggsByDataId := make(map[blocks.AttestationId][]blocks.ROAttestation, 0)
	for id, aggs := range aggregates {
		noCommitteeId := id.IgnoreCommittee()
		existing, ok := aggsByDataId[noCommitteeId]
		if ok {
			aggsByDataId[noCommitteeId] = append(existing, aggs...)
		} else {
			aggsByDataId[noCommitteeId] = aggs
		}
	}

	result := make([]blocks.ROAttestation, 0)

	for _, aggs := range aggsByDataId {
		slices.SortFunc(aggs, func(a, b blocks.ROAttestation) int {
			if a.CommitteeIndex() < b.CommitteeIndex() {
				return -1
			} else if a.CommitteeIndex() == b.CommitteeIndex() {
				return 0
			} else {
				return 1
			}
		})

		sigs := make([]bls.Signature, len(aggs))
		committeeIndices := make([]primitives.CommitteeIndex, len(aggs))
		aggBitsIndices := make([]uint64, 0)
		aggBitsOffset := uint64(0)
		var err error
		for i, a := range aggs {
			for _, bi := range a.GetAggregationBits().BitIndices() {
				aggBitsIndices = append(aggBitsIndices, uint64(bi)+aggBitsOffset)
			}
			sigs[i], err = bls.SignatureFromBytes(a.GetSignature())
			if err != nil {
				return nil, err
			}
			committeeIndices[i] = helpers.CommitteeIndices(a.CommitteeBitsVal())[0]

			aggBitsOffset += a.GetAggregationBits().Len()
		}

		aggregationBits := bitfield.NewBitlist(aggBitsOffset)
		for _, bi := range aggBitsIndices {
			aggregationBits.SetBitAt(bi, true)
		}
		att := &ethpb.AttestationElectra{
			AggregationBits: aggregationBits,
			Data:            aggs[0].GetData(),
			CommitteeBits:   primitives.NewAttestationCommitteeBits(),
			Signature:       bls.AggregateSignatures(sigs).Marshal(),
		}
		for _, ci := range committeeIndices {
			att.CommitteeBits.SetBitAt(uint64(ci), true)
		}
		roAtt, err := blocks.NewROAttestation(att)
		if err != nil {
			return nil, err
		}
		result = append(result, roAtt)
	}

	return result, nil
}
