//go:build wasip1

package main

import "ducat/shared"

const (
	MinThresholdDistance              = shared.MinThresholdDistance
	MaxPriceValue                     = shared.MaxPriceValue
	MaxDomainLength                   = shared.MaxDomainLength
	MinReasonablePrice                = shared.MinReasonablePrice
	MaxReasonablePrice                = shared.MaxReasonablePrice
	MaxPriceStalenessSec              = shared.MaxPriceStalenessSec
	MaxAdjustmentPct                  = shared.MaxAdjustmentPct
	MinAdjustmentPct                  = shared.MinAdjustmentPct
	NostrEventKindThresholdCommitment = shared.NostrEventKindThresholdCommitment
	OriginChainlinkDataStream         = shared.OriginChainlinkDataStream
	EventTypeActive                   = shared.EventTypeActive
	EventTypeBreach                   = shared.EventTypeBreach
)
