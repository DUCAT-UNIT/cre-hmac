//go:build wasip1

package main

import "ducat/shared"

const (
	MinThresholdDistance              = shared.MinThresholdDistance
	MaxPriceValue                     = shared.MaxPriceValue
	MaxDomainLength                   = shared.MaxDomainLength
	MinReasonablePrice                = shared.MinReasonablePrice
	MaxReasonablePrice                = shared.MaxReasonablePrice
	MaxAdjustmentPct                  = shared.MaxAdjustmentPct
	MinAdjustmentPct                  = shared.MinAdjustmentPct
	MaxAdjustmentDurationMin          = shared.MaxAdjustmentDurationMin
	MaxPriceStalenessSec              = shared.MaxPriceStalenessSec
	NostrEventKindThresholdCommitment = shared.NostrEventKindThresholdCommitment
	NostrEventKindContract            = shared.NostrEventKindContract
	NostrEventKindBreach              = shared.NostrEventKindBreach
	OriginChainlinkDataStream         = shared.OriginChainlinkDataStream
	EventTypeActive                   = shared.EventTypeActive
	EventTypeBreach                   = shared.EventTypeBreach
)
