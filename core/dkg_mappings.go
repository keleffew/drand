package core

import (
	"context"
	"errors"
	"github.com/drand/drand/protobuf/drand"
)

type NetworkResponse[Payload any] struct {
	to      *drand.Participant
	payload Payload
}

type FirstProposalSteps struct {
	me *drand.Participant
}

func (p FirstProposalSteps) Enrich(incomingPacket *drand.FirstProposalOptions) (*drand.ProposalTerms, error) {
	return &drand.ProposalTerms{
		BeaconID:  incomingPacket.BeaconID,
		Threshold: incomingPacket.Threshold,
		Epoch:     1,
		Timeout:   incomingPacket.Timeout,
		Leader:    p.me,
		Joining:   incomingPacket.Joining,
		Remaining: nil,
		Leaving:   nil,
	}, nil
}

func (p FirstProposalSteps) Apply(terms *drand.ProposalTerms, currentState *DKGDetails) (*DKGDetails, error) {
	return currentState.Proposing(p.me, terms)
}

func (p FirstProposalSteps) Responses(terms *drand.ProposalTerms, details *DKGDetails) ([]*NetworkResponse[*drand.Proposal], error) {
	proposal := &drand.Proposal{
		Leader:    terms.Leader,
		Threshold: terms.Threshold,
		Timeout:   terms.Timeout,
		Joining:   terms.Joining,
		Remaining: terms.Remaining,
		Leaving:   terms.Leaving,
		Signature: nil,
	}

	var requests []*NetworkResponse[*drand.Proposal]

	for _, joiner := range details.Joining {
		if joiner.Address == p.me.Address {
			continue
		}
		requests = append(requests, &NetworkResponse[*drand.Proposal]{
			to:      joiner,
			payload: proposal,
		})
	}
	return requests, nil
}

func (p FirstProposalSteps) ForwardResponse(client drand.DKGClient, networkCall *NetworkResponse[*drand.Proposal]) error {
	response, err := client.Propose(context.Background(), networkCall.payload)
	if err != nil {
		return err
	}

	if response.IsError {
		return errors.New(response.ErrorMessage)
	}

	return nil
}

type ProposalSteps struct {
	me *drand.Participant
}

func (p ProposalSteps) Enrich(options *drand.ProposalOptions) (*drand.ProposalTerms, error) {
	return &drand.ProposalTerms{
		BeaconID:  options.BeaconID,
		Threshold: options.Threshold,
		Epoch:     2,
		Timeout:   options.Timeout,
		Leader:    p.me,
		Joining:   options.Joining,
		Remaining: options.Remaining,
		Leaving:   options.Leaving,
	}, nil
}

func (p ProposalSteps) Apply(terms *drand.ProposalTerms, currentState *DKGDetails) (*DKGDetails, error) {
	// this should be in enrich, let's move it there later >.>
	terms.Epoch = currentState.Epoch + 1
	return currentState.Proposing(p.me, terms)
}

func (p ProposalSteps) Responses(terms *drand.ProposalTerms, details *DKGDetails) ([]*NetworkResponse[*drand.Proposal], error) {
	proposal := &drand.Proposal{
		Leader:    terms.Leader,
		Threshold: terms.Threshold,
		Timeout:   terms.Timeout,
		Joining:   terms.Joining,
		Remaining: terms.Remaining,
		Leaving:   terms.Leaving,
		Signature: nil,
	}

	var requests []*NetworkResponse[*drand.Proposal]

	for _, joiner := range details.Joining {

		requests = append(requests, &NetworkResponse[*drand.Proposal]{
			to:      joiner,
			payload: proposal,
		})
	}

	for _, remainer := range details.Remaining {
		if remainer.Address == p.me.Address {
			continue
		}
		requests = append(requests, &NetworkResponse[*drand.Proposal]{
			to:      remainer,
			payload: proposal,
		})
	}

	return requests, nil
}

func (p ProposalSteps) ForwardResponse(client drand.DKGClient, networkCall *NetworkResponse[*drand.Proposal]) error {
	response, err := client.Propose(context.Background(), networkCall.payload)
	if err != nil {
		return err
	}

	if response.IsError {
		return errors.New(response.ErrorMessage)
	}

	return nil
}
