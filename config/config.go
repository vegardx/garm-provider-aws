// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Cloudbase Solutions SRL
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package config

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type AWSCredentialType string

const (
	AWSCredentialTypeStatic     AWSCredentialType = "static"
	AWSCredentialTypeRole       AWSCredentialType = "role"
	AWSCredentialTypeAssumeRole AWSCredentialType = "assume_role"
)

// NewConfig returns a new Config
func NewConfig(cfgFile string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(cfgFile, &config); err != nil {
		return nil, fmt.Errorf("error decoding config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config: %w", err)
	}
	return &config, nil
}

type Config struct {
	Credentials Credentials `toml:"credentials"`
	SubnetID    string      `toml:"subnet_id"`
	Region      string      `toml:"region"`
}

func (c *Config) Validate() error {
	if err := c.Credentials.Validate(); err != nil {
		return fmt.Errorf("failed to validate credentials: %w", err)
	}

	if c.SubnetID == "" {
		return fmt.Errorf("missing subnet_id")
	}

	if c.Region == "" {
		return fmt.Errorf("missing region")
	}
	return nil
}

type StaticCredentials struct {
	// AWS Access key ID
	AccessKeyID string `toml:"access_key_id"`

	// AWS Secret Access Key
	SecretAccessKey string `toml:"secret_access_key"`

	// AWS Session Token
	SessionToken string `toml:"session_token"`
}

func (c StaticCredentials) Validate() error {
	if c.AccessKeyID == "" {
		return fmt.Errorf("missing access_key_id")
	}
	if c.SecretAccessKey == "" {
		return fmt.Errorf("missing secret_access_key")
	}

	return nil
}

type AssumeRoleCredentials struct {
	// ARN of the role to assume
	RoleARN string `toml:"role_arn"`

	// Optional session name for CloudTrail auditing
	RoleSessionName string `toml:"role_session_name,omitempty"`

	// Optional external ID for third-party access
	ExternalID string `toml:"external_id,omitempty"`

	// Optional session duration (900-43200 seconds)
	DurationSeconds *int32 `toml:"duration_seconds,omitempty"`
}

func (c AssumeRoleCredentials) Validate() error {
	if c.RoleARN == "" {
		return fmt.Errorf("missing role_arn")
	}
	// Validate ARN format - support different AWS partitions (aws, aws-cn, aws-us-gov)
	if !strings.HasPrefix(c.RoleARN, "arn:aws") || !strings.Contains(c.RoleARN, ":iam::") {
		return fmt.Errorf("invalid role_arn format: must be a valid IAM role ARN")
	}
	// Validate DurationSeconds if provided (AWS STS requirement: 900-43200 seconds)
	if c.DurationSeconds != nil {
		if *c.DurationSeconds < 900 || *c.DurationSeconds > 43200 {
			return fmt.Errorf("invalid duration_seconds: must be between 900 and 43200 seconds")
		}
	}
	return nil
}

type Credentials struct {
	CredentialType        AWSCredentialType     `toml:"credential_type"`
	StaticCredentials     StaticCredentials     `toml:"static"`
	AssumeRoleCredentials AssumeRoleCredentials `toml:"assume_role"`
}

func (c Credentials) Validate() error {
	switch c.CredentialType {
	case AWSCredentialTypeStatic:
		return c.StaticCredentials.Validate()
	case AWSCredentialTypeRole:
		return nil
	case AWSCredentialTypeAssumeRole:
		return c.AssumeRoleCredentials.Validate()
	case "":
		return fmt.Errorf("missing credential_type")
	default:
		return fmt.Errorf("unknown credential type: %s", c.CredentialType)
	}
}

func (c Config) GetAWSConfig(ctx context.Context) (aws.Config, error) {
	if err := c.Credentials.Validate(); err != nil {
		return aws.Config{}, fmt.Errorf("failed to validate credentials: %w", err)
	}

	var cfg aws.Config
	var err error
	switch c.Credentials.CredentialType {
	case AWSCredentialTypeStatic:
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(
					c.Credentials.StaticCredentials.AccessKeyID,
					c.Credentials.StaticCredentials.SecretAccessKey,
					c.Credentials.StaticCredentials.SessionToken)),
			config.WithRegion(c.Region),
		)
	case AWSCredentialTypeRole:
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(c.Region))
	case AWSCredentialTypeAssumeRole:
		// Load base config first
		var baseCfg aws.Config
		baseCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(c.Region))
		if err != nil {
			return aws.Config{}, fmt.Errorf("failed to load base config: %w", err)
		}

		// Create STS client from base config
		stsClient := sts.NewFromConfig(baseCfg)

		// Build assume role options
		assumeRoleOptions := func(o *stscreds.AssumeRoleOptions) {
			if c.Credentials.AssumeRoleCredentials.RoleSessionName != "" {
				o.RoleSessionName = c.Credentials.AssumeRoleCredentials.RoleSessionName
			}
			if c.Credentials.AssumeRoleCredentials.ExternalID != "" {
				o.ExternalID = aws.String(c.Credentials.AssumeRoleCredentials.ExternalID)
			}
			if c.Credentials.AssumeRoleCredentials.DurationSeconds != nil {
				o.Duration = time.Duration(*c.Credentials.AssumeRoleCredentials.DurationSeconds) * time.Second
			}
		}

		// Create credentials provider with assume role
		cfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(c.Region),
			config.WithCredentialsProvider(
				stscreds.NewAssumeRoleProvider(
					stsClient,
					c.Credentials.AssumeRoleCredentials.RoleARN,
					assumeRoleOptions,
				),
			),
		)
	default:
		return aws.Config{}, fmt.Errorf("unknown credential type: %s", c.Credentials.CredentialType)
	}
	if err != nil {
		return aws.Config{}, fmt.Errorf("failed to get aws config: %w", err)
	}
	return cfg, nil
}
