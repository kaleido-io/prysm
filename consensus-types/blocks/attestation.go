package blocks

import (
	"strconv"

	"github.com/prysmaticlabs/prysm/v5/beacon-chain/core/helpers"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v5/runtime/version"
)

// TODO: Doc

type AttestationId struct {
	version        int
	committeeIndex primitives.CommitteeIndex
	digest         [32]byte
}

func (id AttestationId) IgnoreCommittee() AttestationId {
	return AttestationId{
		version:        id.version,
		committeeIndex: 0,
		digest:         id.digest,
	}
}

func (id AttestationId) String() string {
	return strconv.Itoa(id.version) + strconv.FormatUint(uint64(id.committeeIndex), 10) + string(id.digest[:])
}

// TODO: split into aggregated/unaggregated types? what about final aggregate type?
type ROAttestation struct {
	ethpb.Att
	id     AttestationId
	dataId AttestationId
}

func NewROAttestation(att ethpb.Att) (ROAttestation, error) {
	if err := helpers.ValidateNilAttestation(att); err != nil {
		return ROAttestation{}, err
	}

	attRoot, err := att.HashTreeRoot()
	if err != nil {
		return ROAttestation{}, err
	}
	dataRoot, err := att.GetData().HashTreeRoot()
	if err != nil {
		return ROAttestation{}, err
	}

	var committeeIndex primitives.CommitteeIndex
	if att.Version() >= version.Electra {
		committeeIndex = primitives.CommitteeIndex(att.CommitteeBitsVal().BitIndices()[0])
	} else {
		committeeIndex = att.GetData().CommitteeIndex
	}

	return ROAttestation{
		Att:    att,
		id:     AttestationId{version: att.Version(), committeeIndex: committeeIndex, digest: attRoot},
		dataId: AttestationId{version: att.Version(), committeeIndex: committeeIndex, digest: dataRoot},
	}, nil
}

func (a ROAttestation) Id() AttestationId {
	return a.id
}

func (a ROAttestation) DataId() AttestationId {
	return a.dataId
}

func (a ROAttestation) Copy() ROAttestation {
	return ROAttestation{
		Att:    a.Att.Copy(),
		id:     a.id,
		dataId: a.dataId,
	}
}

func (a ROAttestation) CommitteeIndex() primitives.CommitteeIndex {
	if a.Version() == version.Phase0 {
		return a.GetData().CommitteeIndex
	}
	return primitives.CommitteeIndex(uint64(a.CommitteeBitsVal().BitIndices()[0]))
}
