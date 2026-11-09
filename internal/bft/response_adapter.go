package bft

import (
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// The combined certification response carries, besides the operational response and the optional partition view, the signed trust-base entries the root
// offers. This file is the only place that knows its wire type, so a change of the bft-core type is a change here.

// combinedFrom unwraps a received combined response: the operational response (with the partition view in its in-process carrier, status and message
// as sent) and the attached entries, as raw canonical bytes.
func combinedFrom(msg any) (cr *certification.CertificationResponse, updates [][]byte, ok bool) {
	v3, isV3 := msg.(*certification.CertificationResponseV3)
	if !isV3 {
		return nil, nil, false
	}
	updates = make([][]byte, len(v3.TrustBaseUpdates))
	for i, u := range v3.TrustBaseUpdates {
		updates[i] = u
	}
	return v3.Legacy(), updates, true
}

// combinedReceiveProtocol is the receive-protocol registration of the combined response, admitted like the other certification protocols.
func combinedReceiveProtocol(opts NetworkOptions) network.ReceiveProtocolDescription {
	return network.ReceiveProtocolDescription{
		ProtocolID:     network.ProtocolUnicityCertificatesV3,
		MaxFrameSize:   certification.MaxCertificationResponseV3Frame,
		TypeFn:         func() any { return &certification.CertificationResponseV3{} },
		AdmitPeer:      opts.AdmitPeer,
		RevalidatePeer: opts.RevalidatePeer,
	}
}
